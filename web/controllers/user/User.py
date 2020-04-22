from flask import Blueprint,render_template

router_user = Blueprint('user_page',__name__)

@router_user.route("/login")
def login():
    return render_template("user/login.html")

@router_user.route("/logout")
def logout():
    return "登出"

@router_user.route("/edit")
def edit():
    return "编辑"

@router_user.route("/reset-pwd")
def resetPwd():
    return "重置密码"