import datetime
import os
import uuid
from functools import wraps

from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.utils import secure_filename

import app.models as app_models
from app import db, app
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from . import admin


# 上下应用处理器
@admin.context_processor
def tpl_extra():
    date = dict(
        online_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    return date


# 登陆装饰器
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 权限控制器
def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # admin = app_models.Admin.query.join(
        #     app_models.Role
        # ).filter(
        #     app_models.Role.id == app_models.Admin.role_id,
        #     app_models.Admin.id == session["admin_id"]
        # ).first()
        # auths = admin.role.auths
        # auths = list(map(lambda v: int(v), auths.split(",")))
        # auth_list = app_models.Auth.query.all()
        # urls = [v.url for v in auth_list for val in auths if val == v.id]
        # rule = request.url_rule
        # if str(rule) not in urls:
        #     abort(404)
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route('/')
@admin_login_req
def index():
    return render_template('admin/index.html')


# 登陆
@admin.route('/login/', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = app_models.Admin.query.filter_by(name=data['account']).first()
        if not admin:
            flash('账号不存在')
            return redirect(url_for('admin.login'))
        if not admin.check_pwd(data['pwd']):
            flash('密码错误')
            return redirect(url_for('admin.login'))
            # 管理员操作日志
        adminlog = app_models.Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr,
        )
        db.session.add(adminlog)
        db.session.commit()
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


# 修改密码
@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = app_models.Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        redirect(url_for('admin.logout'))
    return render_template("admin/pwd.html", form=form)


# 添加标签
@admin.route('/tag/add/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = app_models.Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash('名称已经存在', 'err')
            return redirect(url_for('admin.tag_add'))
        tag = app_models.Tag(
            name=data['name']
        )
        db.session.add(tag)
        flash('添加标签成功！', 'ok')
        oplog = app_models.Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason='添加标签 - [%s]' % data['name']
        )
        db.session.add(oplog)
        db.session.commit()
        redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


# 标签列表
@admin.route('/tag/list/<int:page>', methods=['GET'])
@admin_login_req
@admin_auth
def tag_list(page=1):
    page_data = app_models.Tag.query.order_by(
        app_models.Tag.addtime.desc()
    ).paginate(page=page, per_page=15)
    return render_template('admin/tag_list.html', page_data=page_data)


# 标签删除
@admin.route('/tag/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def tag_del(id=None):
    tag = app_models.Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('删除标签成功！', 'ok')
    return redirect(url_for('admin.tag_list', page=1))


# 编辑标签
@admin.route('/tag/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = app_models.Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = app_models.Tag.query.filter_by(name=data['name']).count()
        if tag_count == 1 and tag.name != data['name']:
            flash('标签名称已经存在', 'err')
            return redirect(url_for('admin.tag_edit'))
        tag.name = data['name']
        db.session.add(tag)
        oplog = app_models.Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason='修改标签[%s] - [%s]' % (tag.name, data['name'])
        )
        db.session.add(oplog)
        db.session.commit()
        flash('修改标签成功！', 'ok')
        return redirect(url_for('admin.tag_edit', id=id))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


# 添加电影
@admin.route('/movie/add/', methods=['POST', 'GET'])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        movie_count = app_models.Movie.query.filter_by(title=data['title']).count()
        if movie_count >= 1:
            flash('片名已经存在!', 'err')
            return redirect(url_for('admin.movie_add'))

        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)

        movie = app_models.Movie(
            title=data['title'],
            info=data['info'],
            logo='20180305140015b8d9dbef9ac74d15984f6c9fe8e8bb92.jpg',
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )
        db.session.add(movie)
        db.session.commit()
        flash('添加电影成功', 'ok')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


# 电影列表
@admin.route('/movie/list/<int:page>', methods=['GET'])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Movie.query.join(app_models.Tag).filter(
        app_models.Tag.id == app_models.Movie.tag_id
    ).order_by(
        app_models.Movie.addtime.desc()
    ).paginate(page=page, per_page=10)

    return render_template('admin/movie_list.html', page_data=page_data)


# 删除电影
@admin.route('/movie/del/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def movie_del(id=None):
    movie = app_models.Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash('删除电影成功', 'ok')
    return redirect(url_for('admin.movie_list', page=1))


# 编辑电影
@admin.route('/movie/edit/<int:id>/', methods=['POST', 'GET'])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    movie = app_models.Movie.query.get_or_404(int(id))
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = app_models.Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash('片名已经存在!', 'err')
            return redirect(url_for('admin.movie_edit', id=movie.id))

        if form.url.data and form.url.data.filename != '':
            file_url = secure_filename(form.url.data.filename)
            url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + url)

        if form.logo.data and form.logo.data.filename != '':
            file_logo = secure_filename(form.logo.data.filename)
            logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + logo)

        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.title = data['title']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']

        db.session.add(movie)
        db.session.commit()
        flash('修改电影成功', 'ok')
        return redirect(url_for('admin.movie_edit', id=movie.id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


# 添加预告
@admin.route("/preview/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")
        logo = change_filename(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        preview = app_models.Preview(
            title=data["title"],
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash("添加预告成功！", "ok")
        return redirect(url_for('admin.preview_add'))
    return render_template("admin/preview_add.html", form=form)


# 预告列表
@admin.route("/preview/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Preview.query.order_by(
        app_models.Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/preview_list.html", page_data=page_data)


# 删除预告
@admin.route("/preview/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def preview_del(id=None):
    preview = app_models.Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("删除预告成功！", "ok")
    return redirect(url_for('admin.preview_list', page=1))


# 编辑预告
@admin.route("/preview/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_edit(id):
    form = PreviewForm()
    form.logo.validators = []
    preview = app_models.Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + preview.logo)
        preview.title = data["title"]
        db.session.add(preview)
        db.session.commit()
        flash("修改预告成功！", "ok")
        return redirect(url_for('admin.preview_edit', id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


# 会员列表
@admin.route("/user/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.User.query.order_by(
        app_models.User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


# 查看会员
@admin.route("/user/view/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = app_models.User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


# 删除会员
@admin.route("/user/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_del(id=None):
    user = app_models.User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除会员成功！", "ok")
    return redirect(url_for('admin.user_list', page=1))


# 评论列表
@admin.route("/comment/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Comment.query.join(
        app_models.Movie
    ).join(
        app_models.User
    ).filter(
        app_models.Movie.id == app_models.Comment.movie_id,
        app_models.User.id == app_models.Comment.user_id
    ).order_by(
        app_models.Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


# 删除评论
@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def comment_del(id=None):
    comment = app_models.Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除评论成功！", "ok")
    return redirect(url_for('admin.comment_list', page=1))


# 收藏列表
@admin.route("/moviecol/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def moviecol_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Moviecol.query.join(
        app_models.Movie
    ).join(
        app_models.User
    ).filter(
        app_models.Movie.id == app_models.Moviecol.movie_id,
        app_models.User.id == app_models.Moviecol.user_id
    ).order_by(
        app_models.Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


# 收藏删除
@admin.route("/moviecol/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def moviecol_del(id=None):
    moviecol = app_models.Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功！", "ok")
    return redirect(url_for('admin.moviecol_list', page=1))


# 操作日志
@admin.route("/oplog/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Oplog.query.join(
        app_models.Admin
    ).filter(
        app_models.Admin.id == app_models.Oplog.admin_id,
    ).order_by(
        app_models.Oplog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/oplog_list.html", page_data=page_data)


# 管理员登录日志
@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Adminlog.query.join(
        app_models.Admin
    ).filter(
        app_models.Admin.id == app_models.Adminlog.admin_id,
    ).order_by(
        app_models.Adminlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


# 会员登录日志
@admin.route("/userloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Userlog.query.join(
        app_models.User
    ).filter(
        app_models.User.id == app_models.Userlog.user_id,
    ).order_by(
        app_models.Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


# 权限添加
@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = app_models.Auth(
            name=data["name"],
            url=data["url"]
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", "ok")
    return render_template("admin/auth_add.html", form=form)


# 权限列表
@admin.route("/auth/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Auth.query.order_by(
        app_models.Auth.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


# 权限删除
@admin.route("/auth/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_del(id=None):
    auth = app_models.Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除标签成功！", "ok")
    return redirect(url_for('admin.auth_list', page=1))


# 编辑权限
@admin.route("/auth/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = app_models.Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth.url = data["url"]
        auth.name = data["name"]
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！", "ok")
        redirect(url_for('admin.auth_edit', id=id))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


# 添加角色
@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = app_models.Role(
            name=data["name"],
            auths=",".join(map(lambda v: str(v), data["auths"]))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
    return render_template("admin/role_add.html", form=form)


# 编辑角色
@admin.route("/role/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role = app_models.Role.query.get_or_404(id)
    if request.method == "GET":
        auths = role.auths
        form.auths.data = list(map(lambda v: int(v), auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role.name = data["name"]
        role.auths = ",".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！", "ok")
    return render_template("admin/role_edit.html", form=form, role=role)


# 角色列表
@admin.route("/role/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Role.query.order_by(
        app_models.Role.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


# 删除角色
@admin.route("/role/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def role_del(id=None):
    role = app_models.Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！", "ok")
    return redirect(url_for('admin.role_list', page=1))


# 添加管理员
@admin.route("/admin/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = app_models.Admin(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            role_id=data["role_id"],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！", "ok")
    return render_template("admin/admin_add.html", form=form)


# 管理员列表
@admin.route("/admin/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = app_models.Admin.query.join(
        app_models.Role
    ).filter(
        app_models.Role.id == app_models.Admin.role_id
    ).order_by(
        app_models.Admin.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/admin_list.html", page_data=page_data)
