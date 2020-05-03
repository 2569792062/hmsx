from flask import Blueprint,request,jsonify,make_response,redirect,g

from application import app,db
from common.models.User import User
from common.libs.user.UserService import UserService
from common.libs.UrlManager import UrlManager
from common.libs.Helper import ops_render

import json

router_user = Blueprint('user_page',__name__)

# methods可以添加更多的方法
@router_user.route("/login",methods=['GET','POST'])
# 用户登录的函数
def login():
    # 用来获取用户的登录状态
    if request.method == 'GET':
        if g.current_user:
            return redirect(UrlManager.buildUrl("/"))
        return ops_render("user/login.html")
        
    # POST请求
    resp = {
        'code':200,
        'msg':'登录成功',
        'data':{}
    }
    req = request.values
    print('----------------------------------------')
    print(req,'req')
    # 如果账号密码不在req中，值为空
    login_name = req['login_name'] if 'login_name' in req else ''
    login_pwd = req['login_pwd'] if 'login_pwd' in req else ''
    # 对账号密码的校验规则
    # 如果账号为none或者长度小于1
    if login_name is None or len(login_name) < 1:
        resp['code'] = -1
        resp['msg'] = "请输入正确的用户名"
        return jsonify(resp)
    if login_pwd is None or len(login_pwd) < 1:
        resp['code'] = -1
        resp['msg'] = "请输入正确的密码"
        return jsonify(resp)
    # 从数据库中取出user
    # 把获取到的用户名和数据库中进行比较
    user_info = User.query.filter_by(login_name=login_name).first()
    # 如果不存在
    if not user_info:
        resp['code'] = -1
        resp['msg'] = "用户不存在"
        return jsonify(resp)
    # 存在的情况下判断密码是否正确
    # 判断密码
    if user_info.login_pwd != UserService.generatePwd(login_pwd,user_info.login_salt):
        resp['code'] = -1
        resp['msg'] = "密码输入错误"
        return jsonify(resp)
    
    # 判断用户状态
    if user_info.status != 1:
        resp['code'] = -1
        resp['msg'] = "用户已经被禁用，请联系管理员处理"
        return jsonify(resp)
    
    # 以上校验不出问题会登陆成功
    response = make_response(json.dumps({'code':200,'msg':'登录成功~~~'}))
    # Cookie中存入的信息是user_info.uid,user_info
    response.set_cookie(app.config['AUTH_COOKIE_NAME'],"%s@%s"%(UserService.generateAuthCode(user_info),user_info.uid),60*60*24*15)
    return response
    
# 退出函数
@router_user.route("/logout")
def logout():
    # 将浏览器中cookie保存的用户状态信息删除掉
    response = make_response(redirect(UrlManager.buildUrl("/user/login")))
    response.delete_cookie(app.config['AUTH_COOKIE_NAME'])
    return response

# 编辑信息
@router_user.route("/edit",methods=['GET','POST'])
def edit():
    # 如果是get请求返回编辑页面
    if request.method == "GET":
        return ops_render("user/edit.html")
    # POST请求
    resp = {
        'code':200,
        'msg':'编辑成功',
        'data':{}
    }
    # 获取用户信息
    req = request.values
    # 如果账号密码不在req中，值为空
    nickname = req['nickname'] if 'nickname' in req else ''
    email = req['email'] if 'email' in req else ''
    # 如果获取的账号为空或者长度小于1
    if nickname is None or len(nickname) < 1:
        resp['code'] = -1
        resp['msg'] = "请输入规范的nickname"
        return jsonify(resp)
    # 如果获取的邮箱为空或者长度小于1
    if email is None or len(email) < 1:
        resp['code'] = -1
        resp['msg'] = "请输入规范的email"
        return jsonify(resp)
    
    # 别忘了g
    user_info = g.current_user
    user_info.nickname = nickname
    user_info.email = email
    # 将数据库中的信息进行修改
    db.session.add(user_info)
    db.session.commit()
    return jsonify(resp)
    
# 修改密码函数
@router_user.route("/reset-pwd",methods=['GET','POST'])
def resetPwd():
    # get请求返回页面
    if request.method == "GET":
        return ops_render("user/reset_pwd.html")
    # POST请求
    resp = {
        'code':200,
        'msg':'重置密码成功',
        'data':{}
    }
    # 获取用户信息
    req = request.values
    # 如果不在req中返回空
    old_password = req['old_password'] if 'old_password' in req else ''
    new_password = req['new_password'] if 'new_password' in req else ''
    
    # 对新旧密码进行校验
    
    # 如果旧密码为空或者长度小于6
    if old_password is None or len(old_password) < 6:
        resp['code'] = -1
        resp['msg'] = "请输入符合规范的旧密码"
        return jsonify(resp)
    
    # 如果新密码为空或者长度小于6
    if new_password is None or len(new_password) < 6:
        resp['code'] = -1
        resp['msg'] = "请输入符合规范的新密码"
        return jsonify(resp)
    
    # 如果两次密码一样
    if old_password == new_password:
        resp['code'] = -1
        resp['msg'] = "新密码和旧密码不能相同"
        return jsonify(resp)
    
    user_info = g.current_user
    #演示账号的保护
    # if user_info.uid == 1:
    #     pass
    
    user_info.login_pwd = UserService.generatePwd(new_password,user_info.login_salt)

    # 修改数据库中的数据并保存
    db.session.add(user_info)
    db.session.commit()

    # 修改cookie中的旧用户信息
    response = make_response(json.dumps(resp))
    # Cookie中存入的信息是user_info.uid,user_info
    response.set_cookie(app.config['AUTH_COOKIE_NAME'],"%s@%s"%(UserService.generateAuthCode(user_info),user_info.uid),60*60*24*15)
    return response