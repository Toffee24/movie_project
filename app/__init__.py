from flask import Flask, render_template

from app.admin import admin as admin_blueprint
from app.home import home as home_blueprint

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@127.0.0.1:3306/movie?charset=utf8'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app = Flask(__name__)
app.debug = True
# db = SQLAlchemy

# 注册蓝图
app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('home/404.html'),404
