# Adicionar ao app.py após a rota /api/me

# ─── API: ATUALIZAR PERFIL ────────────────────────────────────────────────────
# @app.route('/api/me/update', methods=['PUT'])
# @login_required
# def api_update_me():
#     csrf = request.headers.get('X-CSRF-Token', '')
#     if not validar_csrf(csrf):
#         return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403
#
#     data = request.get_json(silent=True) or {}
#     nome     = sanitizar(data.get('nome', ''), 120)
#     email    = sanitizar(data.get('email', ''), 180).lower()
#     telefone = sanitizar(data.get('telefone', ''), 20)
#     objetivo = sanitizar(data.get('objetivo', ''), 30)
#     plano    = sanitizar(data.get('plano', ''), 20)
#
#     if not nome or len(nome) < 2:
#         return jsonify({'success': False, 'message': 'Nome inválido.'}), 400
#     if not validar_email(email):
#         return jsonify({'success': False, 'message': 'E-mail inválido.'}), 400
#
#     planos_validos = ('mensal','trimestral','semestral','anual','premium')
#     if plano not in planos_validos:
#         return jsonify({'success': False, 'message': 'Plano inválido.'}), 400
#
#     db = get_db()
#     if not db:
#         return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503
#
#     try:
#         cur = db.cursor()
#         cur.execute(
#             "UPDATE usuarios SET nome=%s, email=%s, telefone=%s, objetivo=%s, plano=%s WHERE id=%s",
#             (nome, email, telefone, objetivo, plano, g.user_id)
#         )
#         db.commit()
#         cur.close()
#         return jsonify({'success': True, 'message': 'Perfil atualizado.'})
#     except MySQLError as e:
#         db.rollback()
#         if e.errno == 1062:
#             return jsonify({'success': False, 'message': 'E-mail já em uso.'}), 409
#         log.error("Update error: %s", e)
#         return jsonify({'success': False, 'message': 'Erro interno.'}), 500
