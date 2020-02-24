import os

from flask import Flask
from . import db, auth, blog


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
        DEBUG=True,
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page
    @app.route('/hello')
    def hello():
        return 'hello world'

    # 注册数据库相关函数
    db.init_app(app)

    # 注册认证蓝图
    app.register_blueprint(auth.bp)

    # 注册博客蓝图
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')  # 关联端点名称'index'和 / URL

    app.config['DEBUG'] = True

    return app
