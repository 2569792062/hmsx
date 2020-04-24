from flask import Flask
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
import os

class Applciation(Flask):
    def __init__(self,import_name,template_folder=None,root_path=None):
        super(Applciation, self).__init__(import_name,template_folder=template_folder,root_path=root_path,static_folder=None)
        self.config.from_pyfile('config/base_setting.py')
        db.init_app(self)

db = SQLAlchemy()
app = Applciation(__name__,template_folder=os.getcwd()+'/web/templates/',root_path=os.getcwd())
manager = Manager(app)


from common.libs.UrlManager import UrlManager
app.add_template_global(UrlManager.buildStaticUrl,'buildStaticUrl')
app.add_template_global(UrlManager.buildUrl,'buildUrl')