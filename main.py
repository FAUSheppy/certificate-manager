import OpenSSL
from OpenSSL import crypto
import glob
import flask
import os
import datetime

from sqlalchemy import Column, Integer, String, Boolean, or_, and_
from flask_sqlalchemy import SQLAlchemy


EMPTY_STRING = ""
HTTP_EMPTY = 204
HTTP_BAD_ENTITY = 422
HTTP_NOT_FOUND = 404

CERT_FORMAT_PATH = "./keys/{}_{}.crt"
KEY_FORMAT_PATH = "./keys/{}_{}.key"

app = flask.Flask("Certificate Manager")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sqlite.db"
db = SQLAlchemy(app)

class CertificateEntry(db.Model):

    def __init__(self):

        __tablename__ = "certificates"

        self.serial = Column(Integer, primary_key=True)
        self.name   = Column(String)

        self.vpn = Column(Boolean)
        self.vpn_routed = Column(Boolean)
        self.vpn_allow_outgoing = Column(Boolean)

    def load_privkey(self):

        with open(KEY_FORMAT_PATH.format(self.name, self.serial)) as f:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

def certEntryBySerial(serial):

    result = db.query(CertificateEntry).filter(CertificateEntry.serial == serial).first()
    if not result:
        raise ValueError("No Certificate for serial {} - won't load".format(serial))
    return result

class Certificate:

    def __init__(self, path, serial=None):
       

        if serial:
            print("Loading by serial.. ({})".format(serial))
            self.entry = certEntryBySerial(serial)
            path = CERT_FORMAT_PATH.format(self.entry.name, serial)
        else:
            print("Loading: {}".format(path))

        content = None
        with open(path) as f:
            content = f.read()

        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
        componentTupelList = list(map(lambda x: (x[0].decode(), x[1].decode()), 
                            self.cert.get_subject().get_components()))
        self.components = dict(componentTupelList)

        # load entry late if loaded by path #
        if not serial:
            self.entry = certEntryBySerial(self.cert.get_serial())

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

def getCertBySerial(serial):

    # find correct certificate
    certificates = loadCertificates()
    certResults = list(filter(lambda x: x.cert.get_serial_number(), certificates))
    if not certResults:
        return None
    return certResults[0]

def loadCertificates():
    keysPath = app.config["KEYS_PATH"]
    certificates = [ Certificate(path) for path in 
                        glob.glob(keysPath + "/*.pem") ]
    return certificates

@app.route("/openvpn")
def ovpn():

    serial = flask.request.args.get("serial")
    cert = getCertBySerial(serial)

    server = app.config["VPN_SERVER"]
    port = app.config["VPN_PORT"]

    with open(app.config["CA_CERT_PATH"]) as f:
        caCert = f.read()

    clientCert = cert.cert.dump_certificate(crypto.FILETYPE_PEM)
    clientKey = cert.privkey.dump_privatekey(crypto.FILETYPE_PEM)

    text = flask.render_template("ovpn.j2",
                    server=server,
                    port=port,
                    caCert=caCert,
                    clientCert=clientCert,
                    clientKey=clientKey)

    return flask.Response(text, mimetype="text/xml")

@app.route("/pk12")
def browserCert():

    serial = flask.request.args.get("serial")
    cert = getCertBySerial(serial)

    r = flask.Response(cert.generateP12(b"TEST_TODO"), mimetype="application/octet-stream")
    r.headers["Content-Disposition"] = 'attachment; filename="{}.pk12"'.format(cert.get("CN"))
    return r

def signCertificate(caCert, caKey, csr):

    today = datetime.datetime.today()
    valid_until = today + datetime.timedelta(days=300)
    serial = 0

    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(300)
    cert.set_issuer(caCert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(caKey, 'sha256')

    return cert

@app.route("/create")
def createCert():

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
    L  = flask.request.args("L")      or app.config["L_DEFAULT"]
    O  = flask.request.args("O")      or app.config["O_DEFAULT"]
    OU = flask.request.args("OU")     or app.config["OU_DEFAULT"]

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
    cert = signCertificate(caCert, caKey, req)

    open(CERT_FORMAT_PATH.format(CN, cert.get_serial()), "wt").write(
        str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), "ascii"))
    open(KEY_FORMAT_PATH.format(CN, cert.get_serial()), "wt").write(
        str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key), "ascii"))

    return (EMPTY_STRING, HTTP_EMPTY)


@app.route("/revoke")
def modifyCert():

    serial = flask.request.args.get("serial")
    # Openssl.crypto.load_crl
    basePath = app.config["BASE_PATH"]

@app.route("/cert-info")
def certInfo():

    # get serial number
    serial = flask.request.args.get("serial")
    if not serial:
        return (HTTP_BAD_ENTITY, "Missing Serial Number")

    # find correct certificate
    cert = getCertBySerial(serial)
    if not cert:
        return (HTTP_NOT_FOUND, "No certificate found for serial {}".format(serial))
    
    return flask.render_template("cert_info.html", cert=cert)

@app.route("/")
def root():
    certificates = loadCertificates()
    return flask.render_template("index.html", certificates=certificates)

@app.before_first_request
def init():
    db.create_all()

if __name__ == "__main__":

        app.config["KEYS_PATH"] = "./keys"
        app.config["CA_KEY_PATH"] = "./keys/ca.key"
        app.config["CA_CERT_PATH"] = "./keys/ca.crt"

        app.config["VPN_SERVER"] = "atlantishq.de"
        app.config["VPN_PORT"] = 7012

        app.config["C_DEFAULT"] = "DE"
        app.config["L_DEFAULT"] = "Bavaria"
        app.config["ST_DEFAULT"] = "Erlangen"
        app.config["O_DEFAULT"] = "AtlantisHQ"
        app.config["OU_DEFAULT"] = "Sheppy"

        app.run()
