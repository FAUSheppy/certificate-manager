import main
import data.config as config

def createApp(envivorment=None, start_response=None):
    with main.app.app_context():
        main.app.config.from_object(config)
        main.create_app()
    return main.app
