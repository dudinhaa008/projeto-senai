from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import sqlite3
import os
import hashlib
import secrets
import json
from datetime import datetime
from functools import wraps

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'flowpilot.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Garantir que a pasta de uploads existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Função para conectar ao banco de dados
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Função para inicializar o banco de dados
def init_db():
    with app.app_context():
        db = get_db()
        
        # Tabela de usuários
        db.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                empresa TEXT,
                telefone TEXT,
                plano TEXT DEFAULT 'fundamental',
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ultimo_login TIMESTAMP,
                ativo BOOLEAN DEFAULT 1,
                avatar TEXT
            )
        ''')
        
        # Tabela de processos
        db.execute('''
            CREATE TABLE IF NOT EXISTS processos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                descricao TEXT,
                status TEXT DEFAULT 'pendente',
                usuario_id INTEGER NOT NULL,
                responsavel TEXT,
                categoria TEXT,
                data_inicio DATE,
                data_fim DATE,
                prazo DATE,
                prioridade TEXT DEFAULT 'media',
                progresso INTEGER DEFAULT 0,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de tarefas
        db.execute('''
            CREATE TABLE IF NOT EXISTS tarefas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                processo_id INTEGER NOT NULL,
                nome TEXT NOT NULL,
                descricao TEXT,
                status TEXT DEFAULT 'pendente',
                usuario_id INTEGER NOT NULL,
                ordem INTEGER,
                data_inicio DATE,
                data_fim DATE,
                prazo DATE,
                observacoes TEXT,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (processo_id) REFERENCES processos (id),
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de contatos
        db.execute('''
            CREATE TABLE IF NOT EXISTS contatos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL,
                empresa TEXT,
                telefone TEXT,
                mensagem TEXT NOT NULL,
                data_envio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                lida BOOLEAN DEFAULT 0,
                respondida BOOLEAN DEFAULT 0
            )
        ''')
        
        # Tabela de demonstrações
        db.execute('''
            CREATE TABLE IF NOT EXISTS demonstracoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL,
                empresa TEXT,
                telefone TEXT,
                interesses TEXT,
                data_solicitacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agendada BOOLEAN DEFAULT 0,
                data_agendamento DATE
            )
        ''')
        
        # Tabela de notificações
        db.execute('''
            CREATE TABLE IF NOT EXISTS notificacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                titulo TEXT NOT NULL,
                mensagem TEXT NOT NULL,
                tipo TEXT DEFAULT 'info',
                lida BOOLEAN DEFAULT 0,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de logs de atividades
        db.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                acao TEXT NOT NULL,
                detalhes TEXT,
                ip TEXT,
                user_agent TEXT,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de configurações
        db.execute('''
            CREATE TABLE IF NOT EXISTS configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chave TEXT UNIQUE NOT NULL,
                valor TEXT,
                tipo TEXT DEFAULT 'string'
            )
        ''')
        
        # Inserir configurações padrão
        configs = [
            ('site_nome', 'FlowPilot', 'string'),
            ('site_descricao', 'Simplificando o Futuro e Turbinando sua Equipe', 'string'),
            ('contato_email', 'contato@flowpilot.com', 'string'),
            ('contato_telefone', '+55 (21) 1234-5678', 'string'),
            ('endereco', 'Rio de Janeiro, RJ', 'string'),
            ('planos_ativo', '1', 'boolean'),
            ('demo_ativa', '1', 'boolean')
        ]
        
        for chave, valor, tipo in configs:
            try:
                db.execute('INSERT OR IGNORE INTO configs (chave, valor, tipo) VALUES (?, ?, ?)', 
                          (chave, valor, tipo))
            except:
                pass
        
        db.commit()
        db.close()

# Decorator para login requerido
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Função para log de atividades
def log_acao(acao, detalhes=None):
    try:
        db = get_db()
        db.execute('''
            INSERT INTO logs (usuario_id, acao, detalhes, ip, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (session.get('user_id'), acao, detalhes, 
              request.remote_addr, request.user_agent.string))
        db.commit()
        db.close()
    except:
        pass

# Hash de senha
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

# Rotas principais
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sobre')
def sobre():
    return render_template('index.html')

@app.route('/recursos')
def recursos():
    return render_template('index.html')

@app.route('/planos')
def planos():
    return render_template('index.html')

@app.route('/demonstracao')
def demonstracao():
    return render_template('index.html')

@app.route('/contato')
def contato():
    return render_template('index.html')

# Sistema de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('password')
        
        db = get_db()
        usuario = db.execute('SELECT * FROM usuarios WHERE email = ? AND ativo = 1', 
                            (email,)).fetchone()
        
        if usuario and usuario['senha'] == hash_senha(senha):
            session['user_id'] = usuario['id']
            session['user_nome'] = usuario['nome']
            session['user_email'] = usuario['email']
            session['user_plano'] = usuario['plano']
            
            # Atualizar último login
            db.execute('UPDATE usuarios SET ultimo_login = CURRENT_TIMESTAMP WHERE id = ?', 
                      (usuario['id'],))
            db.commit()
            db.close()
            
            log_acao('LOGIN', f'Usuário {usuario["email"]} logou no sistema')
            flash('Login realizado com sucesso!', 'success')
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        else:
            db.close()
            return jsonify({'success': False, 'message': 'Email ou senha incorretos.'})
    
    return render_template('index.html')

@app.route('/registro', methods=['POST'])
def registro():
    try:
        dados = request.get_json()
        nome = dados.get('nome')
        email = dados.get('email')
        senha = dados.get('senha')
        empresa = dados.get('empresa', '')
        telefone = dados.get('telefone', '')
        
        if not all([nome, email, senha]):
            return jsonify({'success': False, 'message': 'Preencha todos os campos obrigatórios.'})
        
        db = get_db()
        
        # Verificar se email já existe
        if db.execute('SELECT id FROM usuarios WHERE email = ?', (email,)).fetchone():
            db.close()
            return jsonify({'success': False, 'message': 'Este email já está cadastrado.'})
        
        # Criar usuário
        db.execute('''
            INSERT INTO usuarios (nome, email, senha, empresa, telefone, plano)
            VALUES (?, ?, ?, ?, ?, 'fundamental')
        ''', (nome, email, hash_senha(senha), empresa, telefone))
        
        db.commit()
        db.close()
        
        log_acao('REGISTRO', f'Novo usuário registrado: {email}')
        return jsonify({'success': True, 'message': 'Conta criada com sucesso! Faça login.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro ao registrar: {str(e)}'})

@app.route('/logout')
def logout():
    log_acao('LOGOUT', f'Usuário {session.get("user_email")} saiu do sistema')
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    
    # Estatísticas
    stats = db.execute('''
        SELECT 
            (SELECT COUNT(*) FROM processos WHERE usuario_id = ?) as total_processos,
            (SELECT COUNT(*) FROM processos WHERE usuario_id = ? AND status = 'concluido') as processos_concluidos,
            (SELECT COUNT(*) FROM processos WHERE usuario_id = ? AND status = 'pendente') as processos_pendentes,
            (SELECT COUNT(*) FROM tarefas WHERE usuario_id = ? AND status = 'pendente') as tarefas_pendentes
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchone()
    
    # Últimos processos
    processos = db.execute('''
        SELECT * FROM processos 
        WHERE usuario_id = ? 
        ORDER BY data_criacao DESC 
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    # Próximas tarefas
    tarefas = db.execute('''
        SELECT t.*, p.nome as processo_nome 
        FROM tarefas t 
        JOIN processos p ON t.processo_id = p.id 
        WHERE t.usuario_id = ? AND t.status = 'pendente'
        ORDER BY t.prazo ASC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    # Notificações não lidas
    notificacoes = db.execute('''
        SELECT * FROM notificacoes 
        WHERE usuario_id = ? AND lida = 0 
        ORDER BY data_criacao DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    db.close()
    
    return render_template('index.html', 
                         stats=dict(stats),
                         processos=list(processos),
                         tarefas=list(tarefas),
                         notificacoes=list(notificacoes))

# API para processos
@app.route('/api/processos', methods=['GET', 'POST'])
@login_required
def api_processos():
    if request.method == 'GET':
        db = get_db()
        processos = db.execute('''
            SELECT * FROM processos 
            WHERE usuario_id = ? 
            ORDER BY data_criacao DESC
        ''', (session['user_id'],)).fetchall()
        db.close()
        return jsonify([dict(p) for p in processos])
    
    elif request.method == 'POST':
        dados = request.get_json()
        db = get_db()
        
        try:
            cursor = db.execute('''
                INSERT INTO processos (nome, descricao, status, usuario_id, responsavel, 
                                      categoria, data_inicio, data_fim, prazo, prioridade, progresso)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                dados['nome'],
                dados.get('descricao', ''),
                dados.get('status', 'pendente'),
                session['user_id'],
                dados.get('responsavel', ''),
                dados.get('categoria', ''),
                dados.get('data_inicio'),
                dados.get('data_fim'),
                dados.get('prazo'),
                dados.get('prioridade', 'media'),
                dados.get('progresso', 0)
            ))
            
            processo_id = cursor.lastrowid
            db.commit()
            db.close()
            
            log_acao('CRIAR_PROCESSO', f'Processo criado: {dados["nome"]} (ID: {processo_id})')
            return jsonify({'success': True, 'id': processo_id})
        except Exception as e:
            db.close()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/api/processos/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_processo(id):
    db = get_db()
    
    if request.method == 'GET':
        processo = db.execute('SELECT * FROM processos WHERE id = ? AND usuario_id = ?', 
                             (id, session['user_id'])).fetchone()
        if processo:
            tarefas = db.execute('SELECT * FROM tarefas WHERE processo_id = ? ORDER BY ordem', 
                                (id,)).fetchall()
            db.close()
            return jsonify({
                'processo': dict(processo),
                'tarefas': [dict(t) for t in tarefas]
            })
        db.close()
        return jsonify({'error': 'Processo não encontrado'}), 404
    
    elif request.method == 'PUT':
        dados = request.get_json()
        
        # Verificar se o processo pertence ao usuário
        processo = db.execute('SELECT id FROM processos WHERE id = ? AND usuario_id = ?', 
                             (id, session['user_id'])).fetchone()
        if not processo:
            db.close()
            return jsonify({'error': 'Processo não encontrado'}), 404
        
        # Atualizar processo
        campos = []
        valores = []
        
        for campo in ['nome', 'descricao', 'status', 'responsavel', 'categoria', 
                      'data_inicio', 'data_fim', 'prazo', 'prioridade', 'progresso']:
            if campo in dados:
                campos.append(f'{campo} = ?')
                valores.append(dados[campo])
        
        if campos:
            valores.append(id)
            valores.append(session['user_id'])
            query = f'UPDATE processos SET {", ".join(campos)} WHERE id = ? AND usuario_id = ?'
            db.execute(query, valores)
            db.commit()
        
        db.close()
        log_acao('ATUALIZAR_PROCESSO', f'Processo atualizado ID: {id}')
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        # Verificar se o processo pertence ao usuário
        processo = db.execute('SELECT nome FROM processos WHERE id = ? AND usuario_id = ?', 
                             (id, session['user_id'])).fetchone()
        if not processo:
            db.close()
            return jsonify({'error': 'Processo não encontrado'}), 404
        
        # Deletar tarefas primeiro
        db.execute('DELETE FROM tarefas WHERE processo_id = ?', (id,))
        
        # Deletar processo
        db.execute('DELETE FROM processos WHERE id = ? AND usuario_id = ?', 
                  (id, session['user_id']))
        db.commit()
        db.close()
        
        log_acao('DELETAR_PROCESSO', f'Processo deletado: {processo["nome"]} (ID: {id})')
        return jsonify({'success': True})

# API para tarefas
@app.route('/api/tarefas', methods=['POST'])
@login_required
def api_tarefas():
    dados = request.get_json()
    db = get_db()
    
    try:
        cursor = db.execute('''
            INSERT INTO tarefas (processo_id, nome, descricao, status, usuario_id, 
                                ordem, data_inicio, data_fim, prazo, observacoes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            dados['processo_id'],
            dados['nome'],
            dados.get('descricao', ''),
            dados.get('status', 'pendente'),
            session['user_id'],
            dados.get('ordem', 0),
            dados.get('data_inicio'),
            dados.get('data_fim'),
            dados.get('prazo'),
            dados.get('observacoes', '')
        ))
        
        tarefa_id = cursor.lastrowid
        db.commit()
        db.close()
        
        log_acao('CRIAR_TAREFA', f'Tarefa criada: {dados["nome"]} (ID: {tarefa_id})')
        return jsonify({'success': True, 'id': tarefa_id})
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/tarefas/<int:id>', methods=['PUT', 'DELETE'])
@login_required
def api_tarefa(id):
    db = get_db()
    
    if request.method == 'PUT':
        dados = request.get_json()
        
        # Verificar se a tarefa pertence ao usuário
        tarefa = db.execute('SELECT id FROM tarefas WHERE id = ? AND usuario_id = ?', 
                           (id, session['user_id'])).fetchone()
        if not tarefa:
            db.close()
            return jsonify({'error': 'Tarefa não encontrada'}), 404
        
        # Atualizar tarefa
        campos = []
        valores = []
        
        for campo in ['nome', 'descricao', 'status', 'ordem', 'data_inicio', 
                      'data_fim', 'prazo', 'observacoes']:
            if campo in dados:
                campos.append(f'{campo} = ?')
                valores.append(dados[campo])
        
        if campos:
            valores.append(id)
            valores.append(session['user_id'])
            query = f'UPDATE tarefas SET {", ".join(campos)} WHERE id = ? AND usuario_id = ?'
            db.execute(query, valores)
            db.commit()
        
        db.close()
        log_acao('ATUALIZAR_TAREFA', f'Tarefa atualizada ID: {id}')
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        # Verificar se a tarefa pertence ao usuário
        tarefa = db.execute('SELECT nome FROM tarefas WHERE id = ? AND usuario_id = ?', 
                           (id, session['user_id'])).fetchone()
        if not tarefa:
            db.close()
            return jsonify({'error': 'Tarefa não encontrada'}), 404
        
        # Deletar tarefa
        db.execute('DELETE FROM tarefas WHERE id = ? AND usuario_id = ?', 
                  (id, session['user_id']))
        db.commit()
        db.close()
        
        log_acao('DELETAR_TAREFA', f'Tarefa deletada: {tarefa["nome"]} (ID: {id})')
        return jsonify({'success': True})

# API para contatos
@app.route('/api/contato', methods=['POST'])
def api_contato():
    dados = request.get_json()
    
    if not all([dados.get('nome'), dados.get('email'), dados.get('mensagem')]):
        return jsonify({'success': False, 'message': 'Preencha todos os campos obrigatórios.'})
    
    db = get_db()
    
    try:
        db.execute('''
            INSERT INTO contatos (nome, email, empresa, telefone, mensagem)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            dados['nome'],
            dados['email'],
            dados.get('empresa', ''),
            dados.get('telefone', ''),
            dados['mensagem']
        ))
        
        db.commit()
        db.close()
        
        log_acao('ENVIAR_CONTATO', f'Contato enviado por: {dados["email"]}')
        return jsonify({'success': True, 'message': 'Mensagem enviada com sucesso!'})
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'message': str(e)})

# API para demonstrações
@app.route('/api/demo', methods=['POST'])
def api_demo():
    dados = request.get_json()
    
    if not all([dados.get('nome'), dados.get('email')]):
        return jsonify({'success': False, 'message': 'Preencha todos os campos obrigatórios.'})
    
    db = get_db()
    
    try:
        db.execute('''
            INSERT INTO demonstracoes (nome, email, empresa, telefone, interesses)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            dados['nome'],
            dados['email'],
            dados.get('empresa', ''),
            dados.get('telefone', ''),
            dados.get('interesses', '')
        ))
        
        db.commit()
        db.close()
        
        log_acao('SOLICITAR_DEMO', f'Demonstração solicitada por: {dados["email"]}')
        return jsonify({'success': True, 'message': 'Solicitação de demonstração enviada!'})
    except Exception as e:
        db.close()
        return jsonify({'success': False, 'message': str(e)})

# API para perfil
@app.route('/api/perfil', methods=['GET', 'PUT'])
@login_required
def api_perfil():
    db = get_db()
    
    if request.method == 'GET':
        usuario = db.execute('SELECT id, nome, email, empresa, telefone, plano, data_criacao, avatar FROM usuarios WHERE id = ?', 
                            (session['user_id'],)).fetchone()
        db.close()
        return jsonify(dict(usuario))
    
    elif request.method == 'PUT':
        dados = request.get_json()
        
        campos = []
        valores = []
        
        for campo in ['nome', 'empresa', 'telefone']:
            if campo in dados:
                campos.append(f'{campo} = ?')
                valores.append(dados[campo])
        
        if 'senha_atual' in dados and 'nova_senha' in dados:
            # Verificar senha atual
            usuario = db.execute('SELECT senha FROM usuarios WHERE id = ?', 
                                (session['user_id'],)).fetchone()
            
            if usuario['senha'] != hash_senha(dados['senha_atual']):
                db.close()
                return jsonify({'success': False, 'message': 'Senha atual incorreta.'})
            
            campos.append('senha = ?')
            valores.append(hash_senha(dados['nova_senha']))
        
        if campos:
            valores.append(session['user_id'])
            query = f'UPDATE usuarios SET {", ".join(campos)} WHERE id = ?'
            db.execute(query, valores)
            db.commit()
        
        db.close()
        
        # Atualizar sessão se o nome foi alterado
        if 'nome' in dados:
            session['user_nome'] = dados['nome']
        
        log_acao('ATUALIZAR_PERFIL', 'Perfil atualizado')
        return jsonify({'success': True})

# API para estatísticas
@app.route('/api/estatisticas')
@login_required
def api_estatisticas():
    db = get_db()
    
    # Estatísticas gerais
    stats = db.execute('''
        SELECT 
            COUNT(DISTINCT p.id) as total_processos,
            SUM(CASE WHEN p.status = 'concluido' THEN 1 ELSE 0 END) as processos_concluidos,
            SUM(CASE WHEN p.status = 'pendente' THEN 1 ELSE 0 END) as processos_pendentes,
            SUM(CASE WHEN p.status = 'andamento' THEN 1 ELSE 0 END) as processos_andamento,
            COUNT(DISTINCT t.id) as total_tarefas,
            SUM(CASE WHEN t.status = 'concluido' THEN 1 ELSE 0 END) as tarefas_concluidas,
            AVG(p.progresso) as progresso_medio
        FROM processos p
        LEFT JOIN tarefas t ON p.id = t.processo_id
        WHERE p.usuario_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Processos por categoria
    categorias = db.execute('''
        SELECT categoria, COUNT(*) as total
        FROM processos 
        WHERE usuario_id = ? AND categoria IS NOT NULL AND categoria != ''
        GROUP BY categoria
        ORDER BY total DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    # Processos por status
    status_data = db.execute('''
        SELECT status, COUNT(*) as total
        FROM processos 
        WHERE usuario_id = ?
        GROUP BY status
    ''', (session['user_id'],)).fetchall()
    
    db.close()
    
    return jsonify({
        'stats': dict(stats),
        'categorias': [dict(c) for c in categorias],
        'status': [dict(s) for s in status_data]
    })

# Servir arquivos estáticos
@app.route('/<path:filename>')
def serve_static(filename):
    if filename == 'app.py':
        return redirect(url_for('index'))
    return send_from_directory('.', filename)

# Inicializar banco de dados e criar usuário admin
def criar_admin():
    db = get_db()
    
    # Verificar se já existe admin
    admin = db.execute('SELECT id FROM usuarios WHERE email = ?', 
                      ('admin@flowpilot.com',)).fetchone()
    
    if not admin:
        db.execute('''
            INSERT INTO usuarios (nome, email, senha, plano, empresa)
            VALUES (?, ?, ?, ?, ?)
        ''', ('Administrador', 'admin@flowpilot.com', 
              hash_senha('admin123'), 'enterprise', 'FlowPilot'))
        
        db.commit()
        print('Usuário admin criado: admin@flowpilot.com / admin123')
    
    db.close()

# Inicializar aplicação
if __name__ == '__main__':
    # Criar banco de dados se não existir
    if not os.path.exists(app.config['DATABASE']):
        print('Criando banco de dados...')
        init_db()
        criar_admin()
        print('Banco de dados criado com sucesso!')
    
    # Verificar se o admin existe
    criar_admin()
    
    print('\n' + '='*50)
    print('FLOWPILOT - Sistema iniciado com sucesso!')
    print('='*50)
    print(f'URL: http://localhost:5000')
    print(f'Admin: admin@flowpilot.com / admin123')
    print('='*50 + '\n')
    
    app.run(debug=True, port=5000)