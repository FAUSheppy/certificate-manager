import OpenSSL
from OpenSSL import crypto
import glob
import flask
import os
import datetime

HTTP_BAD_ENTITY = 422
HTTP_NOT_FOUND = 404

app = flask.Flask("Certificate Manager")

class CertificateEntry():

        def __init__(self):
            pass
            # VPN options


class Certificate:

    def __init__(self, path):
       
        print("Loading: {}".format(path))
        content = None
        with open(path) as f:
            content = f.read()

        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
        componentTupelList = list(map(lambda x: (x[0].decode(), x[1].decode()), 
                            self.cert.get_subject().get_components()))
        self.components = dict(componentTupelList)

        # TODO
        #self.privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, content)
        
        self.permissions = {
            "nginx" : False,
        }

        if "allow-nginx" in self.get("CN"):
            self.permissions["nginx"] = True

    def get(self, name):
        return self.components.get(name)

    def generateP12(self, password):
        p12 = crypto.PKCS12()
        #p12.set_privatekey(self.privkey)
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

    server = "atlantishq.de"
    port = 7012
    caCert = "TODO"
    clientCert = "TODO"
    clientKey = "TODO"

    text = flask.render_template("ovpn.j2",
                    server=server,
                    port=port,
                    caCert=caCert,
                    clientCert=clientCert,
                    clientKey=clientKey)

    return flask.Response(text, mimetype="text/sml")

@app.route("/pk12")
def browserCert():

    serial = flask.request.args.get("serial")
    cert = getCertBySerial(serial)

    server = "atlantishq.de"
    port = 7012
    caCert = "TODO"
    clientCert = "TODO"
    clientKey = "TODO"

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

    caCert = None
    caKey = None

    with open(app.config["CA_KEY_PATH"]) as f:
        caKey = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    with open(app.config["CA_CERT_PATH"]) as f:
        caCert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    # create a CSR
    CN = "test"
    C = "DE"
    ST = "test"
    L = "test"
    O = "test"
    OU = "test"

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

    open("test.cert", "wt").write(
        str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), "ascii"))
    open("test.key", "wt").write(
        str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key), "ascii"))

    return ("", 204)


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

if __name__ == "__main__":
        app.config["KEYS_PATH"] = "./keys"
        app.config["CA_KEY_PATH"] = "./keys/ca.key"
        app.config["CA_CERT_PATH"] = "./keys/ca.crt"
        app.run()
