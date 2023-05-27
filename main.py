import OpenSSL
from OpenSSL import crypto
import glob
import flask
import os
import sys
import datetime

from sqlalchemy import Column, Integer, String, Boolean, or_, and_, asc, desc
from flask_sqlalchemy import SQLAlchemy


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

class CertificateEntry(db.Model):

    __tablename__ = "certificates"

    serial = Column(Integer, primary_key=True)
    name   = Column(String)

    vpn = Column(Boolean)
    vpn_routed = Column(Boolean)
    vpn_allow_outgoing = Column(Boolean)

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

def load_missing_certificates():

    certs_path = os.path.dirname(CERT_FORMAT_PATH.format(None, None))

    for path in glob.glob(certs_path + "./*"):

        with open(path) as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            serial = cert.get_serial_number()
            cn = cert.get_subject().get_components()[0].decode()

            if (not os.path.is_file(CERT_FORMAT_PATH.format(cn, serial)) or
               not os.path.is_file(KEY_FORMAT_PATH(cn, serial))):
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
        caCert = f.read()

    clientCert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert.cert)
    clientKey = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert.privkey)

    text = flask.render_template("ovpn.j2",
                    server=server,
                    port=port,
                    proto=proto,
                    caCert=caCert.strip("\n"),
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

def sign_certificate(caCert, caKey, csr):

    today = datetime.datetime.today()
    expiry_in = int(datetime.timedelta(days=300).total_seconds())

    cert = crypto.X509()
    cert.set_serial_number(get_min_serial())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(expiry_in)
    cert.set_issuer(caCert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(caKey, 'sha256')

    return cert

@app.route("/create")
def create_cert():

    if not flask.request.args.get("CN"):
        return ("Missing CN argument for certicate creation", HTTP_BAD_ENTITY)

    with open(app.config["CA_KEY_PATH"]) as f:
        caKey = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    with open(app.config["CA_CERT_PATH"]) as f:
        caCert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

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

    req = crypto.X509Req()
    req.get_subject().CN = CN
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L
    req.get_subject().organizationName = O
    req.get_subject().organizationalUnitName = OU

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
    cert = sign_certificate(caCert, caKey, req)

    with open(CERT_FORMAT_PATH.format(CN, cert.get_serial_number()), "wt") as f:
        f.write(str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), "ascii"))

    with open(KEY_FORMAT_PATH.format(CN, cert.get_serial_number()), "wt") as f:
        f.write(str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key), "ascii"))

    db.session.add(CertificateEntry(serial=cert.get_serial_number(), name=CN))
    db.session.commit()

    return (EMPTY_STRING, HTTP_EMPTY)


@app.route("/revoke")
def modify_cert():

    serial = flask.request.args.get("serial")
    # Openssl.crypto.load_crl
    basePath = app.config["BASE_PATH"]

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

        app.run()
