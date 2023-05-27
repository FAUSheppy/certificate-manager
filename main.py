import OpenSSL
from OpenSSL import crypto
import glob
import flask
import os
import sys
import datetime

from sqlalchemy import Column, Integer, String, Boolean, or_, and_, asc, desc
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

EMPTY_STRING = ""
HTTP_EMPTY = 204
HTTP_BAD_ENTITY = 422
HTTP_NOT_FOUND = 404

CERT_FORMAT_PATH = "./keys/{}_{}.crt"
KEY_FORMAT_PATH = "./keys/{}_{}.key"

app = flask.Flask("Certificate Manager")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sqlite.db"
db = SQLAlchemy(app)

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

        with open(KEY_FORMAT_PATH.format(self.name, self.serial)) as f:
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
        self.cert_path = CERT_FORMAT_PATH.format(self.entry.name, self.serial)

        with open(self.cert_path) as f:
            self.cert_content = f.read()

        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_content)

        # load components #
        componentTupelList = list(map(lambda x: (x[0].decode(), x[1].decode()),
                            self.cert.get_subject().get_components()))

        self.components = dict(componentTupelList)
        self.privkey = self.entry.load_privkey()

        self.permissions = {
            "nginx" : False,
        }

        if "allow-nginx" in self.get("CN"):
            self.permissions["nginx"] = True

    def get(self, name):
        return self.components.get(name)

    def generateP12(self, password):
        p12 = crypto.PKCS12()
        p12.set_privatekey(self.privkey)
        p12.set_certificate(self.cert)
        return p12.export(password)

    def is_revoked(self):
        return is_serial_revoked(self.serial)

def load_missing_certificates():

    certs_path = os.path.dirname(CERT_FORMAT_PATH.format(None, None))

    for path in glob.glob(certs_path + "./*"):

        with open(path) as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            serial = cert.get_serial_number()
            cn = cert.get_subject().get_components()[0].decode()

            if (not os.path.isfile(CERT_FORMAT_PATH.format(cn, serial)) or
               not os.path.isfile(KEY_FORMAT_PATH(cn, serial))):
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
                    clientCert=str(clientCert, "ascii").strip("\n"),
                    clientKey=str(clientKey, "ascii").strip("\n"))

    return flask.Response(text, mimetype="text/xml")

@app.route("/pk12")
def browser_cert():

    serial = flask.request.args.get("serial")
    cert = Certificate(serial)

    r = flask.Response(cert.generateP12(b"TEST_TODO"), mimetype="application/octet-stream")
    r.headers["Content-Disposition"] = 'attachment; filename="{}.pk12"'.format(cert.get("CN"))

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
    cert.sign(ca_key, 'sha256')

    return cert

def load_ca():

    with open(app.config["CA_KEY_PATH"]) as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    with open(app.config["CA_CERT_PATH"]) as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    return (ca_key, ca_cert)

@app.route("/create")
def create_cert():

    if not flask.request.args.get("CN"):
        return ("Missing CN argument for certicate creation", HTTP_BAD_ENTITY)

    ca_key, ca_cert = load_ca()

    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    # create a CSR
    CN = flask.request.args.get("CN")
    C  = flask.request.args.get("DE") or app.config["C_DEFAULT"]
    ST = flask.request.args.get("ST") or app.config["ST_DEFAULT"]
    L  = flask.request.args.get("L")  or app.config["L_DEFAULT"]
    O  = flask.request.args.get("O")  or app.config["O_DEFAULT"]
    OU = flask.request.args.get("OU") or app.config["OU_DEFAULT"]
    emailAddress = flask.request.args.get("emailAddress")

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
    x509_extensions = base_constraints
    req.add_extensions(x509_extensions)

    # set CSR key
    req.set_pubkey(key)

    # sign the certificate #
    cert = sign_certificate(ca_cert, ca_key, req)

    with open(CERT_FORMAT_PATH.format(CN, cert.get_serial_number()), "wt") as f:
        f.write(str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), "ascii"))

    with open(KEY_FORMAT_PATH.format(CN, cert.get_serial_number()), "wt") as f:
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

    revokation_list = crl.get_revoked()
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

    with open(crl_path, "wb") as f:
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

    return flask.render_template("cert_info.html", cert=cert)

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
        cert.entry.vpn = vpn_enabled
    if vpn_routed != None:
        cert.entry.vpn_routed = vpn_routed
    if vpn_allow_outgoing != None:
        cert.entry.vpn_allow_outgoing = vpn_allow_outgoing
    if vpn_allow_internal != None:
        cert.entry.vpn_allow_internal = vpn_allow_internal

    vpn_enabled = vpn_enabled == "true"
    vpn_routed = vpn_routed == "true"
    vpn_allow_outgoing = vpn_allow_outgoing == "true"
    vpn_allow_internal = vpn_allow_internal == "true"

    vpn_config_dir_path = app.config["VPN_CONFIG_DIR_PATH"]
    vpn_user_config_path = os.path.join(vpn_config_dir_path, cert.entry.name)
    
    if not vpn_enabled and not cert.entry.vpn:
        if os.path.isfile(vpn_user_config_path):
            os.remove(vpn_user_config_path)
        return (EMPTY_STRING, HTTP_EMPTY)
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

        return (EMPTY_STRING, HTTP_EMPTY)
    
@app.route("/")
def root():

    certificates = [ Certificate(serial=-1, entry=entry)
                        for entry in db.session.query(CertificateEntry).all() ]

    return flask.render_template("index.html", certificates=certificates)

@app.before_first_request
def init():
    db.create_all()
    if app.config["LOAD_MISSING_CERTS_TO_DB"]:
        load_missing_certificates()

if __name__ == "__main__":

        app.config["CRL_PATH"] = "crl.pem"
        app.config["KEYS_PATH"] = "./keys"
        app.config["CA_KEY_PATH"] = "./keys/ca.key"
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

        app.run()
