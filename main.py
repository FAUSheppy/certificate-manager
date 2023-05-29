import OpenSSL
import asn1
import re
from OpenSSL import crypto
import glob
import flask
import os
import sys
import datetime

from sqlalchemy import Column, Integer, String, Boolean, or_, and_, asc, desc
from flask_sqlalchemy import SQLAlchemy

import flask_wtf
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length

import secrets
import telnetlib

EMPTY_STRING = ""
HTTP_EMPTY = 204
HTTP_BAD_ENTITY = 422
HTTP_NOT_FOUND = 404

CERT_FORMAT_PATH = "{}/{}_{}.crt"
KEY_FORMAT_PATH = "{}/{}_{}.key"

app = flask.Flask("Certificate Manager")
CSRFProtect(app)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sqlite.db"

# set different data dir if container #
if os.environ.get("CERT_MANAGER_USE_DATA_DIR") == "true":
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data/sqlite.db"

db = SQLAlchemy(app)

def parse_nginx_maps(subject):

    subjectString = "".join("/{}={}".format(name.decode(), value.decode())
                        for name, value in subject.get_components())

    permissions = dict()

    if not os.path.isfile(app.config["NGINX_CERT_MAPS_LOCATION"]):
        return dict()

    with open(app.config["NGINX_CERT_MAPS_LOCATION"]) as f:
        current_group = None
        for l in f:
            if l.startswith("map $"):
                ignore, s_dn_var, group_var_name, bracket = l.split(" ")
                empty, group_name = group_var_name.split("$allow_group_")
                current_group = group_name
            if "true;" in l:
                clean = l.strip()
                regexString, ignore = clean.split(" ")
                regexString = regexString.replace("~", "") # remove ~ indicator
                result = re.search(regexString, subjectString)
                if result:
                    permissions.update({ group_name : regexString })

    return permissions

def create_ca():

    if os.path.isfile(app.config["CA_KEY_PATH"]):
        error = "Refusing to create new CA because key {} already exists"
        print(error.format(app.config["CA_KEY_PATH"], file=sys.stderr))
        return

    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, app.config["CA_KEY_SIZE"])
    
    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(0)
    
    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = app.config["CA_NAME"]
    
    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    
    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
    ])
    
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
    ])
    
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)
    ca_cert.sign(ca_key, 'sha256')
   
    # ser expiry #
    seconds = int(datetime.timedelta(days=10000).total_seconds())
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(seconds)
    
    # save files #
    with open(app.config["CA_CERT_PATH"], "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    with open(app.config["CA_KEY_PATH"], "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

def openvpn_connect():

    host = app.config["VPN_MANAGEMENT_HOST"]
    port = app.config["VPN_MANAGEMENT_PORT"]
    password = app.config["VPN_MANAGEMENT_PASSWORD"]

    tn = telnetlib.Telnet(host, port)

    tn.read_until(b"PASSWORD: ")
    tn.write(password.encode('ascii') + b"\n")
    tn.read_all()

    return tn

def openvpn_info():

    tn = openvpn_connect()
    tn.write(b"status\n")

    print(tn.read_all().decode('ascii'))

    tn.close()

def openvpn_force_reconnect_client(client_cn):

    tn = openvpn_connect()
    tn.write(b"kill {}\n".format(client_cn))

    print(tn.read_all().decode('ascii'))

    tn.close()

def dump_asn1_timestring(dt):

    return dt.strftime("%Y%m%d%H%M%SZ")

class CertificateEntry(db.Model):

    __tablename__ = "certificates"

    serial = Column(Integer, primary_key=True)
    name   = Column(String)

    vpn = Column(Boolean)
    vpn_allow_internal = Column(Boolean)
    vpn_routed = Column(Boolean)
    vpn_allow_outgoing = Column(Boolean)

    ip_in_block = Column(Integer)

    def load_privkey(self):

        with open(KEY_FORMAT_PATH.format(app.config["KEYS_PATH"], self.name, self.serial)) as f:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

def get_min_serial():

    entry = db.session.query(CertificateEntry).order_by(desc(CertificateEntry.serial)).first()
    if not entry:
        return 1 # ca is zero
    else:
        return entry.serial + 1

def get_entry_by_serial(serial):

    result = db.session.query(CertificateEntry).filter(CertificateEntry.serial == serial).first()
    if not result:
        raise ValueError("No Certificate for serial {} - won't load".format(serial))

    return result

class Certificate:

    def __init__(self, serial, entry=None):

        if entry:
            self.entry = entry
        else:
            self.entry = get_entry_by_serial(serial)

        self.serial = self.entry.serial
        self.cert_path = CERT_FORMAT_PATH.format(app.config["KEYS_PATH"], self.entry.name, self.serial)

        with open(self.cert_path) as f:
            self.cert_content = f.read()

        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_content)

        self.extensions = []
        for i in range(0, self.cert.get_extension_count()):
            self.extensions.append(self.cert.get_extension(i))

        # load components #
        componentTupelList = list(map(lambda x: (x[0].decode(), x[1].decode()),
                            self.cert.get_subject().get_components()))

        self.components = dict(componentTupelList)
        self.privkey = self.entry.load_privkey()

        self.permissions = {
            "nginx" : False,
        }

        self.permissions = parse_nginx_maps(self.cert.get_subject())

    def ext_decode(self, ext):

        data = ext.get_data()
        decoder = asn1.Decoder()
        decoder.start(data)
        tag, value = decoder.read()
        return value.decode("ascii")


    def get(self, name):
        return self.components.get(name)

    def generateP12(self, password):
        p12 = crypto.PKCS12()
        p12.set_privatekey(self.privkey)
        p12.set_certificate(self.cert)
        return p12.export(password)

    def is_revoked(self):
        return is_serial_revoked(self.serial)

    def is_revoked_js(self):
        '''Return a true/false string for javascript templates'''
        return "true" if is_serial_revoked(self.serial) else "false"


def load_missing_certificates():

    certs_path = os.path.dirname(CERT_FORMAT_PATH.format(None, None, None))

    for path in glob.glob(certs_path + "./*"):

        with open(path) as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            serial = cert.get_serial_number()
            cn = cert.get_subject().get_components()[0].decode()

            if (not os.path.isfile(CERT_FORMAT_PATH.format(app.config["KEYS_PATH"], cn, serial)) or
               not os.path.isfile(KEY_FORMAT_PATH(app.config["KEYS_PATH"], cn, serial))):
                print("Bad naming scheme '{}' (skipping..)".format(path), file=sys.stderr)

            try:
                entry = get_entry_by_serial(serial)
                if entry:
                    print("Not adding {} - serial already exists in DB".format(path))
            except ValueError:
                entry = CertificateEntry(serial=serial, name=cn)
                db.add(entry)
                db.commit()

@app.route("/openvpn")
def ovpn():

    serial = flask.request.args.get("serial")
    cert = Certificate(serial)

    server = app.config["VPN_SERVER"]
    port = app.config["VPN_PORT"]
    proto = app.config["VPN_PROTO"]

    with open(app.config["CA_CERT_PATH"]) as f:
        ca_cert = f.read()

    clientCert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert.cert)
    clientKey = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert.privkey)

    text = flask.render_template("ovpn.j2",
                    server=server,
                    port=port,
                    proto=proto,
                    ca_cert=ca_cert.strip("\n"),
                    client_cert=str(clientCert, "ascii").strip("\n"),
                    client_key=str(clientKey, "ascii").strip("\n"))

    r = flask.Response(text, mimetype="application/octet-stream")
    r.headers["Content-Disposition"] = 'attachment; filename="{}.ovpn"'.format(cert.get("CN"))
    return r

@app.route("/pk12")
def browser_cert():

    serial = flask.request.args.get("serial")
    tmp_pw = flask.request.args.get("tmp_pw").encode("ascii")
    cert = Certificate(serial)

    r = flask.Response(cert.generateP12(tmp_pw), mimetype="application/octet-stream")
    r.headers["Content-Disposition"] = 'attachment; filename="{}.pfx"'.format(cert.get("CN"))

    return r

def sign_certificate(ca_cert, ca_key, csr):

    today = datetime.datetime.today()
    expiry_in = int(datetime.timedelta(days=300).total_seconds())

    cert = crypto.X509()
    cert.set_serial_number(get_min_serial())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(expiry_in)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    
    # extensions #
    cert.add_extensions(csr.get_extensions())

    cert.sign(ca_key, 'sha256')

    return cert

def load_ca():

    with open(app.config["CA_KEY_PATH"]) as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    with open(app.config["CA_CERT_PATH"]) as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    return (ca_key, ca_cert)

class CreateCertForm(FlaskForm):

    name = StringField('CN/Name', validators=[DataRequired()])
    email = StringField('E-Mail')
    country = StringField('Country')
    location = StringField('Location')
    state = StringField('State')
    org = StringField('Organisation')
    org_unit = StringField('Organistation Unit')

    code_signing_allowed = BooleanField("Allow signing code")
    server_auth_allowed  = BooleanField("Allow authentication servers")
    email_sign_allowed   = BooleanField("Allow S/MIME usage")


@app.route("/create-interface", methods=["GET", "POST"])
def create_interface():

    form = CreateCertForm()
    if form.validate_on_submit():
        create_cert(form)
        return flask.redirect('/')
    return flask.render_template('create_cert_form.html', form=form)

def create_cert(form):

    ca_key, ca_cert = load_ca()

    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, app.config["CA_KEY_SIZE"])

    # create a CSR
    CN = form.name.data
    if not CN:
        raise ValueError("Missing CN for certificate creation")

    C  = form.country.data or app.config["C_DEFAULT"]
    ST = form.state.data or app.config["ST_DEFAULT"]
    L  = form.location.data or app.config["L_DEFAULT"]
    O  = form.org.data or app.config["O_DEFAULT"]
    OU = form.org_unit.data or app.config["OU_DEFAULT"]
    emailAddress = form.email.data

    req = crypto.X509Req()
    req.get_subject().CN = CN
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L
    req.get_subject().organizationName = O
    req.get_subject().organizationalUnitName = OU

    if emailAddress:
        req.get_subject().emailAddress = emailAddress

    # Add CSR extensions
    base_constraints = ([
        crypto.X509Extension(b"keyUsage", False,
                b"Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    # extened Key usaged extensions #
    extended_key_usage = []
    if form.code_signing_allowed.data:
        extended_key_usage += ["codeSigning"]

    if form.email_sign_allowed.data:
        extended_key_usage += ["emailProtection"]

    if form.server_auth_allowed.data:
        extended_key_usage += ["serverAuth"]

    extended_key_usage_string = ", ".join(extended_key_usage)
    if any((form.code_signing_allowed.data, form.email_sign_allowed.data, form.server_auth_allowed.data)):
        x509_exku = crypto.X509Extension(b"extendedKeyUsage", False, extended_key_usage_string.encode("ascii"))
        base_constraints.append(x509_exku)

    x509_extensions = base_constraints
    req.add_extensions(x509_extensions)

    # set CSR key
    req.set_pubkey(key)

    # sign the certificate #
    cert = sign_certificate(ca_cert, ca_key, req)

    with open(CERT_FORMAT_PATH.format(app.config["KEYS_PATH"], CN, cert.get_serial_number()), "wt") as f:
        f.write(str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), "ascii"))

    with open(KEY_FORMAT_PATH.format(app.config["KEYS_PATH"], CN, cert.get_serial_number()), "wt") as f:
        f.write(str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key), "ascii"))

    db.session.add(CertificateEntry(serial=cert.get_serial_number(), name=CN))
    db.session.commit()

    return (EMPTY_STRING, HTTP_EMPTY)


def load_crl():

    crl_path = app.config["CRL_PATH"]
    if os.path.isfile(crl_path) and not os.stat(crl_path).st_size == 0:
        with open(crl_path) as f:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, f.read())
    else:
        crl = crypto.CRL()

    return crl

def is_serial_revoked(serial, crl=None):

    if not crl:
        crl = load_crl()

    revokation_list = crl.get_revoked() or []
    serials_in_revokation_list = [ int(r.get_serial()) for r in  revokation_list ]

    if int(serial) in serials_in_revokation_list:
        return revokation_list[serials_in_revokation_list.index(int(serial))]
    else:
        return None

@app.route("/revoke")
def revoke():

    serial = flask.request.args.get("serial")
    reason = flask.request.args.get("reason") or "unspecified"

    ca_key, ca_cert = load_ca()
    crl = load_crl()

    if is_serial_revoked(serial, crl):
        return ("Serial {} is already revoked".format(serial), HTTP_BAD_ENTITY)

    asn1_today = dump_asn1_timestring(datetime.datetime.now())
    crl.set_lastUpdate(asn1_today.encode("ascii"))

    # build revokation #
    revokation = crypto.Revoked()
    revokation.set_serial(str(serial).encode("ascii"))
    revokation.set_rev_date(asn1_today.encode("ascii"))

    try:
        revokation.set_reason(reason.encode("ascii"))
    except ValueError:
        return ("{} is not a valid revokation reason in x509".format(reason), HTTP_BAD_ENTITY)

    # add to revokation to crl & sign #
    crl.add_revoked(revokation)
    crl.sign(ca_cert, ca_key, b"sha256")

    with open(app.config["CRL_PATH"], "wb") as f:
        f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

    return (EMPTY_STRING, HTTP_EMPTY)

@app.route("/cert-info")
def cert_info():

    # get serial number
    serial = flask.request.args.get("serial")
    if not serial:
        return ("Missing Serial Number", HTTP_BAD_ENTITY)

    # find correct certificate
    try:
        cert = Certificate(serial)
    except ValueError as e:
        print(e, file=sys.stderr)
        return ("No certificate found for serial {}".format(serial), HTTP_NOT_FOUND)

    # precompute cause jinja
    checkedDict = dict()
    checkedDict["vpn_enabled"]        = "checked" if cert.entry.vpn                else ""
    checkedDict["vpn_routed"]         = "checked" if cert.entry.vpn_routed         else ""
    checkedDict["vpn_allow_internal"] = "checked" if cert.entry.vpn_allow_internal else ""
    checkedDict["vpn_allow_outgoing"] = "checked" if cert.entry.vpn_allow_outgoing else ""

    return flask.render_template("cert_info.html", cert=cert, checked=checkedDict)

@app.route("/vpn")
def vpn():

    serial = flask.request.args.get("serial")
    if not serial:
        return ("Missing 'serial' URL argument", HTTP_BAD_ENTITY)
    else:
        serial = int(serial)

    cert = Certificate(serial)

    vpn_enabled = flask.request.args.get("vpn_enabled")
    vpn_routed = flask.request.args.get("vpn_routed")
    vpn_allow_outgoing = flask.request.args.get("vpn_allow_outgoing")
    vpn_allow_internal = flask.request.args.get("vpn_allow_internal")

    if vpn_enabled != None:
        cert.entry.vpn = vpn_enabled == "true"
    if vpn_routed != None:
        cert.entry.vpn_routed = vpn_routed == "true"
    if vpn_allow_outgoing != None:
        cert.entry.vpn_allow_outgoing = vpn_allow_outgoing == "true"
    if vpn_allow_internal != None:
        cert.entry.vpn_allow_internal = vpn_allow_internal == "true"

    vpn_config_dir_path = app.config["VPN_CONFIG_DIR_PATH"]
    vpn_user_config_path = os.path.join(vpn_config_dir_path, cert.entry.name)
    
    if not cert.entry.vpn:
        if os.path.isfile(vpn_user_config_path):
            os.remove(vpn_user_config_path)
    else:

        # 2-50    routed + outgoing + internal
        # 51-100  routed
        # 101-150 internal
        # 151-200 internal + outgoing
        # 201-250 only server & outgoing

        if cert.entry.vpn_routed and cert.entry.vpn_allow_outgoing:
            base_ip = 1
        elif cert.entry.vpn_routed and not cert.entry.vpn_allow_internal:
            base_ip = 51
        elif cert.entry.vpn_allow_internal and not cert.entry.vpn_allow_outgoing:
            base_ip = 101
        elif cert.entry.vpn_allow_internal and cert.entry.vpn_allow_outgoing:
            base_ip = 151
        elif cert.entry.vpn_allow_outgoing and not cert.entry.vpn_allow_internal:
            base_ip = 201
        else:
            base_ip = 101

        if serial >= 50:
            raise NotImplementedError("Currenly only 50 certificates are supported for VPN")
       
        ipv4_format = "ifconfig-push 172.16.1.{} 255.255.255.0".format(base_ip + serial)
        ipv6_format = "ifconfig-ipv6-push fd2a:aef:608:1::{}/64".format(base_ip + serial + 1000)

        print("Setting IP as {}".format(ipv4_format))

        with open(vpn_user_config_path, "w") as f:
            f.write(ipv4_format)
            f.write("\n")
            f.write(ipv6_format)

    db.session.merge(cert.entry)
    db.session.commit()
    return (EMPTY_STRING, HTTP_EMPTY)
    
@app.route("/")
def root():

    certificates = [ Certificate(serial=-1, entry=entry)
                        for entry in db.session.query(CertificateEntry).all() ]

    return flask.render_template("index.html", certificates=certificates)

def create_app():

    app.config["SECRET_KEY"] = secrets.token_urlsafe(64)
    db.create_all()

    if app.config["CREATE_CA_IF_NOT_EXISTS"]:
        create_ca()

    if app.config["LOAD_MISSING_CERTS_TO_DB"]:
        load_missing_certificates()

if __name__ == "__main__":

        app.config["CREATE_CA_IF_NOT_EXISTS"] = True
        app.config["CRL_PATH"] = "crl.pem"
        app.config["KEYS_PATH"] = "./keys"
        app.config["CA_KEY_SIZE"] = 2048
        app.config["CA_NAME"] = "AtlantisHQv2"
        app.config["CA_KEY_PATH"] = "./keys/ca.key"
        app.config["CA_CERT_PATH"] = "./keys/ca.crt"
        app.config["CA_CERT_PATH"] = "./keys/ca.crt"

        app.config["VPN_SERVER"] = "atlantishq.de"
        app.config["VPN_PORT"] = 7012
        app.config["VPN_PROTO"] = "tcp"

        app.config["C_DEFAULT"] = "DE"
        app.config["L_DEFAULT"] = "Bavaria"
        app.config["ST_DEFAULT"] = "Erlangen"
        app.config["O_DEFAULT"] = "AtlantisHQ"
        app.config["OU_DEFAULT"] = "Sheppy"

        app.config["LOAD_MISSING_CERTS_TO_DB"] = True
        app.config["VPN_CONFIG_DIR_PATH"] = "./ccd/"

        app.config["ENABLE_VPN_CONNECTION"] = False
        app.config["VPN_MANAGEMENT_HOST"] = "localhost"
        app.config["VPN_MANAGEMENT_PORT"] = 23000
        app.config["VPN_MANAGEMENT_PASSWORD"] = ""

        app.config["NGINX_CERT_MAPS_LOCATION"] = "./nginx_maps.j2"

        with app.app_context():
            create_app()
        app.run()
