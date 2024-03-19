from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from .import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email = email). first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logado com sucesso!', category='Sucesso')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Email ou senha incorreto(s)!', category= 'Erro')
        else:
            flash('Email não existe!', category='Erro')
            
    return render_template("login.html", user= current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method =='POST':
        
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email = email).first()
        if user:
            flash('Este email ja existe!', category='Erro')
        elif len(email) < 4:
            flash('Seu endereço de email deve ser maior do que 4 caracteres!', category='Erro')
        elif len(first_name) < 2:
            flash('Primeiro nome deve ser maior do que 2 caracteres!', category='Erro')
        elif password1 != password2:
            flash('Senhas devem ser iguais!', category='Erro')
        elif len(password1) < 7:
            flash('Senhas devem ter no mínimo 7 caracteres!', category='Erro')
        else:
            new_user = User(email = email, first_name = first_name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Conta criada com sucesso!', category='Sucesso')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)