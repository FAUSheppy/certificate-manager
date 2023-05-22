import OpenSSL.crypto
import glob
import flask
import os

HTTP_BAD_ENTITY = 422
HTTP_NOT_FOUND = 404

app = flask.Flask("Certificate Manager")

class Certificate:

    def __init__(self, path):
       
        print("Loading: {}".format(path))
        content = None
        with open(path) as f:
            content = f.read()

        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
        componentTupelList = list(map(lambda x: (x[0].decode(), x[1].decode()), 
                            self.cert.get_subject().get_components()))
        self.components = dict(componentTupelList)
        
        self.permissions = {
            "nginx" : False,
        }

        if "allow-nginx" in self.get("CN"):
            self.permissions["nginx"] = True

    def get(self, name):
        return self.components.get(name)

def loadCertificates():
    keysPath = app.config["KEYS_PATH"]
    certificates = [ Certificate(path) for path in 
                        glob.glob(keysPath + "/*.pem") ]
    return certificates

@app.route("/modify")
def modifyCert():

    serial = flask.request.args.get("serial")
    action = flask.request.args.get("action")

    if action == "create":
        pass
    elif action == "revoke":
        pass

    basePath = app.config["BASE_PATH"]

@app.route("/cert-info")
def certInfo():

    # get serial number
    serial = flask.request.args.get("serial")
    if not serial:
        return (HTTP_BAD_ENTITY, "Missing Serial Number")

    # find correct certificate
    certificates = loadCertificates()
    certResults = list(filter(lambda x: x.cert.get_serial_number(), certificates))
    if not certResults:
        return (HTTP_NOT_FOUND, "No certificate found for serial {}".format(serial))
    cert = certResults[0]
    
    return flask.render_template("cert_info.html", cert=cert)

@app.route("/")
def root():
    certificates = loadCertificates()
    return flask.render_template("index.html", certificates=certificates)

if __name__ == "__main__":
        app.config["KEYS_PATH"] = "./keys"
        app.run()
