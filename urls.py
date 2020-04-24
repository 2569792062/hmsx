from application import app
from web.controllers.user.User import router_user
from web.controllers.index import route_index
from web.controllers.static import route_static

app.register_blueprint(router_user,url_prefix="/user")
app.register_blueprint(route_index,url_prefix="/")  
app.register_blueprint(route_static,url_prefix="/static")