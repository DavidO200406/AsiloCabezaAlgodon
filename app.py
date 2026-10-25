from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from datetime import datetime
import mysql.connector
import os
import math
from decimal import Decimal, InvalidOperation

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

# =========================================================
# CONEXIÓN A LA BASE DE DATOS
# =========================================================

def obtener_conexion():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# =========================================================
# CONTROL DE ACCESO POR ROL
# =========================================================

def requiere_rol(*roles_permitidos):

    def decorador(funcion):

        @wraps(funcion)
        def funcion_protegida(*args, **kwargs):

            if "usuario_id" not in session:
                return redirect(url_for("login"))

            rol_usuario = session.get("rol")

            if rol_usuario not in roles_permitidos:
                return render_template(
                    "acceso_denegado.html",
                    rol_usuario=rol_usuario
                ), 403

            return funcion(*args, **kwargs)

        return funcion_protegida

    return decorador


# =========================================================
# LOGIN
# =========================================================

@app.route("/")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def procesar_login():

    usuario = request.form.get("usuario", "").strip()
    contraseña = request.form.get("contraseña", "")

    if not usuario or not contraseña:
        return render_template(
            "login.html",
            error="Ingresa tu usuario y contraseña."
        )

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:

        consulta = """
            SELECT
                u.id_usuario,
                u.nombre_usuario,
                u.contrasena,
                u.nombre_completo,
                u.id_rol,
                u.estado,
                r.nombre AS rol
            FROM usuarios u
            INNER JOIN roles r
                ON u.id_rol = r.id_rol
            WHERE u.nombre_usuario = %s
              AND u.estado = TRUE
        """

        cursor.execute(consulta, (usuario,))
        usuario_encontrado = cursor.fetchone()

        if not usuario_encontrado:
            return render_template(
                "login.html",
                error="Usuario o contraseña incorrectos."
            )

        contraseña_guardada = usuario_encontrado["contrasena"]

        # -------------------------------------------------
        # VERIFICAR CONTRASEÑA
        # -------------------------------------------------

        if contraseña_guardada.startswith(("scrypt:", "pbkdf2:")):

            contraseña_valida = check_password_hash(
                contraseña_guardada,
                contraseña
            )

        else:

            
            contraseña_valida = (
                contraseña_guardada == contraseña
            )

            if contraseña_valida:

                nuevo_hash = generate_password_hash(
                    contraseña
                )

                cursor.execute(
                    """
                    UPDATE usuarios
                    SET contrasena = %s
                    WHERE id_usuario = %s
                    """,
                    (
                        nuevo_hash,
                        usuario_encontrado["id_usuario"]
                    )
                )

                conexion.commit()

        
        if not contraseña_valida:
            return render_template(
                "login.html",
                error="Usuario o contraseña incorrectos."
            )

        # -------------------------------------------------
        # CREAR SESIÓN
        # -------------------------------------------------

        session.clear()

        session["usuario_id"] = usuario_encontrado["id_usuario"]
        session["nombre_usuario"] = usuario_encontrado["nombre_usuario"]
        session["nombre_completo"] = usuario_encontrado["nombre_completo"]
        session["id_rol"] = usuario_encontrado["id_rol"]
        session["rol"] = usuario_encontrado["rol"]

        return redirect(url_for("inicio"))

    finally:

        cursor.close()
        conexion.close()

# =========================================================
# PANEL PRINCIPAL
# =========================================================

@app.route("/inicio")
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico",
    "Contador"
)
def inicio():

    return render_template("inicio.html")

# =========================================================
# RESIDENTES: LISTADO Y BÚSQUEDA
# =========================================================
@app.route("/residentes", methods=["GET"])
@requiere_rol("Administrador", "Recepcionista")
def residentes():
    busqueda = request.args.get("busqueda", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        consulta = """
            SELECT
                id_interno,
                nombres,
                apellidos,
                fecha_nacimiento,
                fecha_ingreso,
                genero,
                motivo_ingreso,
                diagnostico_ingreso,
                estado
            FROM internos
        """

        if busqueda:
            consulta += """
                WHERE CONCAT(nombres, ' ', apellidos) LIKE %s
                   OR nombres LIKE %s
                   OR apellidos LIKE %s
            """

            parametro = f"%{busqueda}%"
            cursor.execute(
                consulta + " ORDER BY apellidos, nombres",
                (parametro, parametro, parametro)
            )
        else:
            consulta += " ORDER BY apellidos, nombres"
            cursor.execute(consulta)

        internos = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "residentes.html",
        internos=internos,
        busqueda=busqueda
    )

# =========================================================
# RESIDENTES: NUEVO REGISTRO
# =========================================================
@app.route("/residentes/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador", "Recepcionista")
def nuevo_residente():

    if request.method == "POST":

        # Datos del residente
        nombres = request.form.get("nombres", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        fecha_nacimiento = request.form.get("fecha_nacimiento", "")
        fecha_ingreso = request.form.get("fecha_ingreso", "")
        genero = request.form.get("genero", "")
        motivo_ingreso = request.form.get("motivo_ingreso", "").strip()
        diagnostico_ingreso = request.form.get("diagnostico_ingreso", "").strip()
        medicamentos_cajon = request.form.get("medicamentos_cajon", "").strip()
        observaciones = request.form.get("observaciones", "").strip()

        # Datos del familiar
        familiar_nombres = request.form.get("familiar_nombres", "").strip()
        familiar_apellidos = request.form.get("familiar_apellidos", "").strip()
        parentesco = request.form.get("parentesco", "")
        familiar_telefono = request.form.get("familiar_telefono", "").strip()
        familiar_correo = request.form.get("familiar_correo", "").strip()
        familiar_direccion = request.form.get("familiar_direccion", "").strip()
        responsable_pago = 1 if request.form.get("responsable_pago") else 0

        # Validar campos obligatorios
        if not all([
            nombres,
            apellidos,
            fecha_nacimiento,
            fecha_ingreso,
            familiar_nombres,
            familiar_apellidos,
            parentesco
        ]):
            return render_template(
                "residente_formulario.html",
                error="Completa todos los campos obligatorios."
            )

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            # Guardar residente
            consulta_interno = """
                INSERT INTO internos (
                    nombres,
                    apellidos,
                    fecha_nacimiento,
                    fecha_ingreso,
                    genero,
                    motivo_ingreso,
                    diagnostico_ingreso,
                    medicamentos_cajon,
                    observaciones
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                consulta_interno,
                (
                    nombres,
                    apellidos,
                    fecha_nacimiento,
                    fecha_ingreso,
                    genero or None,
                    motivo_ingreso or None,
                    diagnostico_ingreso or None,
                    medicamentos_cajon or None,
                    observaciones or None
                )
            )

            id_interno = cursor.lastrowid

            # Guardar familiar relacionado con el residente
            consulta_familiar = """
                INSERT INTO familiares (
                    id_interno,
                    nombres,
                    apellidos,
                    parentesco,
                    telefono,
                    correo,
                    direccion,
                    responsable_pago
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                consulta_familiar,
                (
                    id_interno,
                    familiar_nombres,
                    familiar_apellidos,
                    parentesco,
                    familiar_telefono or None,
                    familiar_correo or None,
                    familiar_direccion or None,
                    responsable_pago
                )
            )

            conexion.commit()

        except Exception:
            conexion.rollback()
            raise

        finally:
            cursor.close()
            conexion.close()

        return redirect(url_for("residentes"))

    return render_template("residente_formulario.html")

# =========================================================
# DETALLE DE RESIDENTE
# =========================================================

@app.route("/residentes/<int:id_interno>")
@requiere_rol(
    "Administrador",
    "Recepcionista"
)
def detalle_residente(id_interno):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    consulta = """
        SELECT
            id_interno,
            nombres,
            apellidos,
            fecha_nacimiento,
            fecha_ingreso,
            genero,
            motivo_ingreso,
            diagnostico_ingreso,
            medicamentos_cajon,
            observaciones,
            estado
        FROM internos
        WHERE id_interno = %s
    """

    cursor.execute(consulta, (id_interno,))
    interno = cursor.fetchone()

    cursor.close()
    conexion.close()

    if not interno:
        return "Residente no encontrado", 404

    return render_template(
        "detalle_residente.html",
        interno=interno
    )

# =========================================================
# EDITAR RESIDENTE
# =========================================================

@app.route("/residentes/<int:id_interno>/editar", methods=["GET", "POST"])
@requiere_rol(
    "Administrador",
    "Recepcionista"
)
def editar_residente(id_interno):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # -----------------------------------------------------
    # OBTENER RESIDENTE
    # -----------------------------------------------------

    cursor.execute(
        """
        SELECT
            id_interno,
            nombres,
            apellidos,
            fecha_nacimiento,
            fecha_ingreso,
            genero,
            motivo_ingreso,
            diagnostico_ingreso,
            medicamentos_cajon,
            observaciones,
            estado
        FROM internos
        WHERE id_interno = %s
        """,
        (id_interno,)
    )

    interno = cursor.fetchone()

    if not interno:
        cursor.close()
        conexion.close()
        return "Residente no encontrado", 404

    # -----------------------------------------------------
    # ACTUALIZAR RESIDENTE
    # -----------------------------------------------------

    if request.method == "POST":

        nombres = request.form.get("nombres")
        apellidos = request.form.get("apellidos")
        fecha_nacimiento = request.form.get("fecha_nacimiento")
        fecha_ingreso = request.form.get("fecha_ingreso")
        genero = request.form.get("genero")
        motivo_ingreso = request.form.get("motivo_ingreso")
        diagnostico_ingreso = request.form.get("diagnostico_ingreso")
        medicamentos_cajon = request.form.get("medicamentos_cajon")
        observaciones = request.form.get("observaciones")

        consulta = """
            UPDATE internos
            SET
                nombres = %s,
                apellidos = %s,
                fecha_nacimiento = %s,
                fecha_ingreso = %s,
                genero = %s,
                motivo_ingreso = %s,
                diagnostico_ingreso = %s,
                medicamentos_cajon = %s,
                observaciones = %s
            WHERE id_interno = %s
        """

        valores = (
            nombres,
            apellidos,
            fecha_nacimiento,
            fecha_ingreso,
            genero,
            motivo_ingreso,
            diagnostico_ingreso,
            medicamentos_cajon,
            observaciones,
            id_interno
        )

        cursor.execute(consulta, valores)
        conexion.commit()

        cursor.close()
        conexion.close()

        return redirect(url_for("residentes")
        )

    cursor.close()
    conexion.close()

    return render_template(
        "editar_residente.html",
        interno=interno
    )


# =========================================================
# MÓDULO FAMILIARES
# =========================================================

@app.route("/familiares")
@requiere_rol("Administrador")
def familiares():

    busqueda = request.args.get("buscar", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        consulta = """
            SELECT
                f.id_familiar,
                f.id_interno,
                f.nombres,
                f.apellidos,
                f.parentesco,
                f.telefono,
                f.correo,
                f.direccion,
                f.responsable_pago,
                i.nombres AS nombre_residente,
                i.apellidos AS apellido_residente
            FROM familiares f
            INNER JOIN internos i
                ON f.id_interno = i.id_interno
        """

        
        if busqueda:
            consulta += """
                WHERE CONCAT(f.nombres, ' ', f.apellidos) LIKE %s
                   OR f.nombres LIKE %s
                   OR f.apellidos LIKE %s
                   OR CONCAT(i.nombres, ' ', i.apellidos) LIKE %s
                   OR i.nombres LIKE %s
                   OR i.apellidos LIKE %s
            """

            parametro = f"%{busqueda}%"
            cursor.execute(
                consulta + " ORDER BY f.apellidos, f.nombres",
                (
                    parametro,
                    parametro,
                    parametro,
                    parametro,
                    parametro,
                    parametro
                )
            )
        else:
            cursor.execute(
                consulta + " ORDER BY f.apellidos, f.nombres"
            )

        lista_familiares = cursor.fetchall()

        return render_template(
            "familiares.html",
            familiares=lista_familiares,
            busqueda=busqueda,
            estado=request.args.get("estado", "")
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# REDACTAR CORREO PARA UN FAMILIAR
# =========================================================

@app.route("/familiares/<int:id_familiar>/correo", methods=["GET"])
@requiere_rol("Administrador")
def redactar_correo(id_familiar):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                f.id_familiar,
                f.nombres,
                f.apellidos,
                f.correo,
                i.nombres AS nombre_residente,
                i.apellidos AS apellido_residente
            FROM familiares f
            INNER JOIN internos i
                ON f.id_interno = i.id_interno
            WHERE f.id_familiar = %s
        """, (id_familiar,))

        familiar = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    if not familiar:
        return "Familiar no encontrado.", 404

    if not familiar["correo"]:
        return redirect(
            url_for("familiares", estado="sin_correo")
        )

    return render_template(
        "redactar_correo.html",
        familiar=familiar
    )


# =========================================================
# CONFIRMAR ENVÍO DEL CORREO
# =========================================================

@app.route(
    "/familiares/<int:id_familiar>/enviar-correo",
    methods=["POST"]
)
@requiere_rol("Administrador")
def enviar_correo_familiar(id_familiar):

    asunto = request.form.get("asunto", "").strip()
    mensaje = request.form.get("mensaje", "").strip()

    if not asunto or not mensaje:
        return redirect(
            url_for(
                "redactar_correo",
                id_familiar=id_familiar
            )
        )

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id_familiar, correo
            FROM familiares
            WHERE id_familiar = %s
        """, (id_familiar,))

        familiar = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    if not familiar:
        return "Familiar no encontrado.", 404

    if not familiar["correo"]:
        return redirect(
            url_for("familiares", estado="sin_correo")
        )

    return redirect(
        url_for("familiares", estado="enviado")
    )

# =========================================================
# Personal Medico
# ========================================================= 
@app.route("/personal")
@requiere_rol("Administrador")
def personal():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                m.id_medico,
                m.nombres,
                m.apellidos,
                m.colegiado,
                m.telefono,
                m.correo,
                m.estado,
                e.nombre AS especialidad
            FROM medicos m
            INNER JOIN especialidades e
                ON m.id_especialidad = e.id_especialidad
            ORDER BY m.apellidos, m.nombres
        """)
        medicos = cursor.fetchall()

        cursor.execute("""
            SELECT
                id_enfermero,
                nombres,
                apellidos,
                telefono,
                correo,
                estado
            FROM enfermeros
            ORDER BY apellidos, nombres
        """)
        enfermeros = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "personal.html",
        medicos=medicos,
        enfermeros=enfermeros
    )

# ============================================================
# Mostrar formulario y registrar médicos o enfermeros
# ============================================================
@app.route("/personal/<tipo>/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador")
def nuevo_personal(tipo):
    if tipo not in ["medico", "enfermero"]:
        return "Tipo de personal no válido.", 404

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)
    error = None
    especialidades = []

    try:
        if tipo == "medico":
            cursor.execute("""
                SELECT id_especialidad, nombre
                FROM especialidades
                ORDER BY nombre
            """)
            especialidades = cursor.fetchall()

        if request.method == "POST":
            nombres = request.form.get("nombres", "").strip()
            apellidos = request.form.get("apellidos", "").strip()
            telefono = request.form.get("telefono", "").strip() or None
            correo = request.form.get("correo", "").strip() or None

            if not nombres or not apellidos:
                error = "Los nombres y apellidos son obligatorios."

            elif tipo == "medico":
                colegiado = request.form.get("colegiado", "").strip() or None
                id_especialidad = request.form.get("id_especialidad", "").strip()

                if not id_especialidad.isdigit():
                    error = "Selecciona una especialidad válida."

                else:
                    cursor.execute("""
                        SELECT id_especialidad
                        FROM especialidades
                        WHERE id_especialidad = %s
                    """, (int(id_especialidad),))

                    especialidad = cursor.fetchone()

                    if not especialidad:
                        error = "La especialidad seleccionada no existe."

                    else:
                        try:
                            cursor.execute("""
                                INSERT INTO medicos
                                    (nombres, apellidos, colegiado, telefono,
                                     correo, id_especialidad, estado)
                                VALUES (%s, %s, %s, %s, %s, %s, 1)
                            """, (
                                nombres,
                                apellidos,
                                colegiado,
                                telefono,
                                correo,
                                int(id_especialidad)
                            ))
                            conexion.commit()
                            return redirect(url_for("personal"))

                        except Exception:
                            conexion.rollback()
                            error = (
                                "No se pudo registrar el médico. "
                                "Verifica que el número de colegiado "
                                "no esté registrado previamente."
                            )

            else:
                try:
                    cursor.execute("""
                        INSERT INTO enfermeros
                            (nombres, apellidos, telefono, correo, estado)
                        VALUES (%s, %s, %s, %s, 1)
                    """, (nombres, apellidos, telefono, correo))

                    conexion.commit()
                    return redirect(url_for("personal"))

                except Exception:
                    conexion.rollback()
                    error = "No se pudo registrar al enfermero."

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "personal_formulario.html",
        tipo=tipo,
        especialidades=especialidades,
        error=error
    )


# =========================================================
# SOLICITUDES MÉDICAS
# =========================================================

@app.route("/solicitudes-medicas", methods=["GET", "POST"])
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def solicitudes_medicas():

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    if request.method == "POST":

        id_interno = request.form.get("id_interno")
        id_medico_solicitado = request.form.get("id_medico_solicitado")
        id_enfermero = request.form.get("id_enfermero")
        motivo = request.form.get("motivo")
        observaciones = request.form.get("observaciones")

        if not id_medico_solicitado:
            id_medico_solicitado = None

        if not id_enfermero:
            id_enfermero = None

        consulta = """
            INSERT INTO solicitudes_medicas (
                id_interno,
                id_medico_solicitado,
                id_enfermero,
                motivo,
                observaciones
            )
            VALUES (%s, %s, %s, %s, %s)
        """

        valores = (
            id_interno,
            id_medico_solicitado,
            id_enfermero,
            motivo,
            observaciones
        )

        cursor.execute(consulta, valores)
        conexion.commit()

        cursor.close()
        conexion.close()

        return redirect(url_for("solicitudes_medicas"))

    # =====================================================
    # OBTENER RESIDENTES
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_interno,
            nombres,
            apellidos
        FROM internos
        WHERE estado = 'Activo'
        ORDER BY apellidos, nombres
        """
    )

    residentes = cursor.fetchall()

    # =====================================================
    # OBTENER MÉDICOS
    # =====================================================

    cursor.execute(
        """
        SELECT
            m.id_medico,
            m.nombres,
            m.apellidos,
            e.nombre AS especialidad
        FROM medicos m
        LEFT JOIN especialidades e
            ON m.id_especialidad = e.id_especialidad
        ORDER BY m.apellidos, m.nombres
        """
    )

    medicos = cursor.fetchall()

    # =====================================================
    # OBTENER ENFERMEROS
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_enfermero,
            nombres,
            apellidos
        FROM enfermeros
        ORDER BY apellidos, nombres
        """
    )

    enfermeros = cursor.fetchall()

    # =====================================================
    # OBTENER SOLICITUDES
    # =====================================================

    cursor.execute(
        """
        SELECT
            s.id_solicitud,
            s.id_interno,
            s.id_medico_solicitado,
            s.id_enfermero,
            s.fecha_solicitud,
            s.motivo,
            s.estado,
            s.observaciones,

            i.nombres AS residente_nombres,
            i.apellidos AS residente_apellidos,

            m.nombres AS medico_nombres,
            m.apellidos AS medico_apellidos,

            e.nombres AS enfermero_nombres,
            e.apellidos AS enfermero_apellidos

        FROM solicitudes_medicas s

        INNER JOIN internos i
            ON s.id_interno = i.id_interno

        LEFT JOIN medicos m
            ON s.id_medico_solicitado = m.id_medico

        LEFT JOIN enfermeros e
            ON s.id_enfermero = e.id_enfermero

        ORDER BY s.fecha_solicitud DESC
        """
    )

    solicitudes = cursor.fetchall()

    cursor.close()
    conexion.close()

    return render_template(
        "solicitudes_medicas.html",
        residentes=residentes,
        medicos=medicos,
        enfermeros=enfermeros,
        solicitudes=solicitudes
    )

# =========================================================
# DETALLE DE SOLICITUD MÉDICA
# =========================================================

@app.route("/solicitudes-medicas/<int:id_solicitud>")
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def detalle_solicitud_medica(id_solicitud):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            s.id_solicitud,
            s.id_interno,
            s.id_medico_solicitado,
            s.id_enfermero,
            s.fecha_solicitud,
            s.motivo,
            s.estado,
            s.observaciones,

            i.nombres AS residente_nombres,
            i.apellidos AS residente_apellidos,

            m.nombres AS medico_nombres,
            m.apellidos AS medico_apellidos,

            e.nombres AS enfermero_nombres,
            e.apellidos AS enfermero_apellidos

        FROM solicitudes_medicas s

        INNER JOIN internos i
            ON s.id_interno = i.id_interno

        LEFT JOIN medicos m
            ON s.id_medico_solicitado = m.id_medico

        LEFT JOIN enfermeros e
            ON s.id_enfermero = e.id_enfermero

        WHERE s.id_solicitud = %s
        """,
        (id_solicitud,)
    )

    solicitud = cursor.fetchone()

    cursor.close()
    conexion.close()

    if not solicitud:
        return "Solicitud médica no encontrada", 404

    return render_template(
        "detalle_solicitud_medica.html",
        solicitud=solicitud
    )

    # =========================================================
# EDITAR SOLICITUD MÉDICA
# =========================================================

@app.route(
    "/solicitudes-medicas/<int:id_solicitud>/editar",
    methods=["GET", "POST"]
)
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def editar_solicitud_medica(id_solicitud):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    # =====================================================
    # OBTENER SOLICITUD
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_solicitud,
            id_interno,
            id_medico_solicitado,
            id_enfermero,
            fecha_solicitud,
            motivo,
            estado,
            observaciones
        FROM solicitudes_medicas
        WHERE id_solicitud = %s
        """,
        (id_solicitud,)
    )

    solicitud = cursor.fetchone()

    if not solicitud:

        cursor.close()
        conexion.close()

        return "Solicitud médica no encontrada", 404


    # =====================================================
    # GUARDAR CAMBIOS
    # =====================================================

    if request.method == "POST":

        id_interno = request.form.get("id_interno")

        id_medico_solicitado = request.form.get(
            "id_medico_solicitado"
        )

        id_enfermero = request.form.get(
            "id_enfermero"
        )

        motivo = request.form.get("motivo")

        estado = request.form.get("estado")

        observaciones = request.form.get(
            "observaciones"
        )


        if not id_medico_solicitado:
            id_medico_solicitado = None

        if not id_enfermero:
            id_enfermero = None


        consulta = """
            UPDATE solicitudes_medicas

            SET
                id_interno = %s,
                id_medico_solicitado = %s,
                id_enfermero = %s,
                motivo = %s,
                estado = %s,
                observaciones = %s

            WHERE id_solicitud = %s
        """


        valores = (
            id_interno,
            id_medico_solicitado,
            id_enfermero,
            motivo,
            estado,
            observaciones,
            id_solicitud
        )


        cursor.execute(
            consulta,
            valores
        )

        conexion.commit()

        cursor.close()
        conexion.close()


        return redirect(
            url_for(
                "detalle_solicitud_medica",
                id_solicitud=id_solicitud
            )
        )


    # =====================================================
    # RESIDENTES
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_interno,
            nombres,
            apellidos
        FROM internos
        WHERE estado = 'Activo'
        ORDER BY apellidos, nombres
        """
    )

    residentes = cursor.fetchall()


    # =====================================================
    # MÉDICOS
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_medico,
            nombres,
            apellidos
        FROM medicos
        ORDER BY apellidos, nombres
        """
    )

    medicos = cursor.fetchall()


    # =====================================================
    # ENFERMEROS
    # =====================================================

    cursor.execute(
        """
        SELECT
            id_enfermero,
            nombres,
            apellidos
        FROM enfermeros
        ORDER BY apellidos, nombres
        """
    )

    enfermeros = cursor.fetchall()


    cursor.close()
    conexion.close()


    return render_template(
        "editar_solicitud_medica.html",
        solicitud=solicitud,
        residentes=residentes,
        medicos=medicos,
        enfermeros=enfermeros
    )

# =========================================================
# CITAS MÉDICAS
# =========================================================

@app.route("/citas-medicas", methods=["GET", "POST"])
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def citas_medicas():

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:

        
        # -------------------------------------------------
        # REGISTRAR CITA MÉDICA
        # -------------------------------------------------

        if request.method == "POST":

            id_solicitud = request.form.get("id_solicitud")
            id_medico = request.form.get("id_medico")
            fecha_cita = request.form.get("fecha_cita")
            observaciones = request.form.get(
                "observaciones", ""
            ).strip()

            if not id_solicitud or not id_medico or not fecha_cita:
                return (
                    "Debes seleccionar una solicitud, "
                    "un médico y una fecha y hora.",
                    400
                )

            try:
                fecha_cita_dt = datetime.strptime(
                    fecha_cita, "%Y-%m-%dT%H:%M"
                )
            except ValueError:
                return "La fecha y hora no son válidas.", 400

            if fecha_cita_dt <= datetime.now():
                return (
                    "La fecha y hora de la cita deben ser futuras.",
                    400
                )

            fecha_cita = fecha_cita_dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            cursor.execute(
                """
                SELECT id_solicitud
                FROM solicitudes_medicas
                WHERE id_solicitud = %s
                """,
                (id_solicitud,)
            )

            if not cursor.fetchone():
                return "La solicitud médica seleccionada no existe.", 400

            cursor.execute(
                """
                SELECT id_medico
                FROM medicos
                WHERE id_medico = %s
                """,
                (id_medico,)
            )

            if not cursor.fetchone():
                return "El médico seleccionado no existe.", 400

            cursor.execute(
                """
                INSERT INTO citas_medicas (
                    id_solicitud,
                    id_medico,
                    fecha_cita,
                    observaciones
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    id_solicitud,
                    id_medico,
                    fecha_cita,
                    observaciones or None
                )
            )

            conexion.commit()

            return redirect(url_for("citas_medicas"))


        # -------------------------------------------------
        # OBTENER SOLICITUDES MÉDICAS
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                s.id_solicitud,
                s.id_medico_solicitado,
                s.motivo,
                s.estado,
                i.nombres AS residente_nombres,
                i.apellidos AS residente_apellidos,
                m.nombres AS medico_nombres,
                m.apellidos AS medico_apellidos,
                e.nombre AS especialidad
            FROM solicitudes_medicas s
            INNER JOIN internos i
                ON s.id_interno = i.id_interno
            LEFT JOIN medicos m
                ON s.id_medico_solicitado = m.id_medico
            LEFT JOIN especialidades e
                ON m.id_especialidad = e.id_especialidad
            ORDER BY s.fecha_solicitud DESC
        """)

        solicitudes = cursor.fetchall()

        # -------------------------------------------------
        # OBTENER MÉDICOS ACTIVOS
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                m.id_medico,
                m.nombres,
                m.apellidos,
                e.nombre AS especialidad
            FROM medicos m
            LEFT JOIN especialidades e
                ON m.id_especialidad = e.id_especialidad
            WHERE m.estado = 1
            ORDER BY m.apellidos, m.nombres
        """)

        medicos = cursor.fetchall()

        # -------------------------------------------------
        # CONSULTAR CITAS MÉDICAS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                c.id_cita,
                c.id_solicitud,
                c.id_medico,
                c.fecha_cita,
                c.estado,
                c.observaciones,

                s.motivo,

                i.nombres AS residente_nombres,
                i.apellidos AS residente_apellidos,

                m.nombres AS medico_nombres,
                m.apellidos AS medico_apellidos

            FROM citas_medicas c

            INNER JOIN solicitudes_medicas s
                ON c.id_solicitud = s.id_solicitud

            INNER JOIN internos i
                ON s.id_interno = i.id_interno

            INNER JOIN medicos m
                ON c.id_medico = m.id_medico

            ORDER BY c.fecha_cita DESC
            """
        )

        citas = cursor.fetchall()

        return render_template(
            "citas_medicas.html",
            solicitudes=solicitudes,
            medicos=medicos,
            citas=citas
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# DETALLE DE UNA CITA MÉDICA
# =========================================================

@app.route("/citas-medicas/<int:id_cita>")
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def detalle_cita_medica(id_cita):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                c.id_cita,
                c.fecha_cita,
                c.estado,
                c.observaciones,
                s.id_solicitud,
                s.motivo,
                s.estado AS estado_solicitud,
                i.nombres AS residente_nombres,
                i.apellidos AS residente_apellidos,
                m.nombres AS medico_nombres,
                m.apellidos AS medico_apellidos
            FROM citas_medicas c
            INNER JOIN solicitudes_medicas s
                ON c.id_solicitud = s.id_solicitud
            INNER JOIN internos i
                ON s.id_interno = i.id_interno
            INNER JOIN medicos m
                ON c.id_medico = m.id_medico
            WHERE c.id_cita = %s
            """,
            (id_cita,)
        )

        cita = cursor.fetchone()

        if not cita:
            return "La cita médica no existe.", 404

        return render_template(
            "detalle_cita_medica.html",
            cita=cita
        )

    finally:
        cursor.close()
        conexion.close()


# =========================================================
# EDITAR CITA MÉDICA
# =========================================================

@app.route("/citas-medicas/<int:id_cita>/editar", methods=["GET", "POST"])
@requiere_rol(
    "Administrador",
    "Recepcionista",
    "Enfermero",
    "Medico"
)
def editar_cita_medica(id_cita):

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM citas_medicas
            WHERE id_cita = %s
            """,
            (id_cita,)
        )
        cita = cursor.fetchone()

        if not cita:
            return "La cita médica no existe.", 404

        if request.method == "POST":
            id_solicitud = request.form.get("id_solicitud")
            id_medico = request.form.get("id_medico")
            fecha_cita = request.form.get("fecha_cita")
            estado = request.form.get("estado")
            observaciones = request.form.get(
                "observaciones", ""
            ).strip()

            estados_permitidos = [
                "Programada",
                "Realizada",
                "Cancelada"
            ]

            if (
                not id_solicitud
                or not id_medico
                or not fecha_cita
                or estado not in estados_permitidos
            ):
                return (
                    "Completa los campos obligatorios "
                    "y selecciona un estado válido.",
                    400
                )

            try:
                fecha_cita_dt = datetime.strptime(
                    fecha_cita, "%Y-%m-%dT%H:%M"
                )
            except ValueError:
                return "La fecha y hora no son válidas.", 400

            if fecha_cita_dt <= datetime.now():
                return (
                    "La fecha y hora de la cita deben ser futuras.",
                    400
                )

            fecha_cita = fecha_cita_dt.strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute(
                """
                SELECT id_solicitud
                FROM solicitudes_medicas
                WHERE id_solicitud = %s
                """,
                (id_solicitud,)
            )

            if not cursor.fetchone():
                return "La solicitud médica seleccionada no existe.", 400

            cursor.execute(
                """
                SELECT id_medico
                FROM medicos
                WHERE id_medico = %s
                """,
                (id_medico,)
            )

            if not cursor.fetchone():
                return "El médico seleccionado no existe.", 400

            cursor.execute(
                """
                UPDATE citas_medicas
                SET
                    id_solicitud = %s,
                    id_medico = %s,
                    fecha_cita = %s,
                    estado = %s,
                    observaciones = %s
                WHERE id_cita = %s
                """,
                (
                    id_solicitud,
                    id_medico,
                    fecha_cita,
                    estado,
                    observaciones or None,
                    id_cita
                )
            )

            conexion.commit()

            return redirect(
                url_for(
                    "detalle_cita_medica",
                    id_cita=id_cita
                )
            )

        cursor.execute(
            """
            SELECT
                s.id_solicitud,
                s.motivo,
                i.nombres AS residente_nombres,
                i.apellidos AS residente_apellidos
            FROM solicitudes_medicas s
            INNER JOIN internos i
                ON s.id_interno = i.id_interno
            ORDER BY s.fecha_solicitud DESC
            """
        )
        solicitudes = cursor.fetchall()

        cursor.execute(
            """
            SELECT id_medico, nombres, apellidos
            FROM medicos
            WHERE estado = 1 OR id_medico = %s
            ORDER BY apellidos, nombres
            """,
            (cita["id_medico"],)
        )
        medicos = cursor.fetchall()

        return render_template(
            "editar_cita_medica.html",
            cita=cita,
            solicitudes=solicitudes,
            medicos=medicos
        )

    finally:
        cursor.close()
        conexion.close()

# ==========================================
# MODULO DE MEDICAMENTOS
# ==========================================

@app.route("/medicamentos")
@requiere_rol("Administrador", "Enfermero", "Medico")
def medicamentos():
    busqueda = request.args.get("busqueda", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        if busqueda:
            cursor.execute("""
                SELECT id_medicamento, nombre, descripcion,
                       presentacion, unidad_medida, stock, estado
                FROM medicamentos
                WHERE nombre LIKE %s OR descripcion LIKE %s
                ORDER BY nombre
            """, (f"%{busqueda}%", f"%{busqueda}%"))
        else:
            cursor.execute("""
                SELECT id_medicamento, nombre, descripcion,
                       presentacion, unidad_medida, stock, estado
                FROM medicamentos
                ORDER BY nombre
            """)

        lista_medicamentos = cursor.fetchall()

        return render_template(
            "medicamentos.html",
            medicamentos=lista_medicamentos,
            busqueda=busqueda,
            mensaje=request.args.get("mensaje", "")
        )
    finally:
        cursor.close()
        conexion.close()


@app.route("/medicamentos/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador")
def nuevo_medicamento():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        presentacion = request.form.get("presentacion", "").strip()
        unidad_medida = request.form.get("unidad_medida", "").strip()
        stock_texto = request.form.get("stock", "").strip()
        estado = 1 if request.form.get("estado") == "1" else 0

        if not nombre:
            return render_template(
                "medicamento_formulario.html",
                medicamento=request.form,
                error="El nombre del medicamento es obligatorio."
            )

        try:
            stock = int(stock_texto)
            if stock < 0:
                raise ValueError
        except ValueError:
            return render_template(
                "medicamento_formulario.html",
                medicamento=request.form,
                error="Las existencias deben ser un número entero igual o mayor que cero."
            )

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute("""
                INSERT INTO medicamentos
                    (nombre, descripcion, presentacion,
                     unidad_medida, stock, estado)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                nombre,
                descripcion or None,
                presentacion or None,
                unidad_medida or None,
                stock,
                estado
            ))

            conexion.commit()
        finally:
            cursor.close()
            conexion.close()

        return redirect(url_for(
            "medicamentos",
            mensaje="registrado"
        ))

    return render_template(
        "medicamento_formulario.html",
        medicamento=None,
        error=""
    )


@app.route("/medicamentos/<int:id_medicamento>/editar",
           methods=["GET", "POST"])
@requiere_rol("Administrador")
def editar_medicamento(id_medicamento):
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id_medicamento, nombre, descripcion,
                   presentacion, unidad_medida, stock, estado
            FROM medicamentos
            WHERE id_medicamento = %s
        """, (id_medicamento,))

        medicamento = cursor.fetchone()

        if not medicamento:
            return redirect(url_for(
                "medicamentos",
                mensaje="no_encontrado"
            ))

        if request.method == "POST":
            nombre = request.form.get("nombre", "").strip()
            descripcion = request.form.get("descripcion", "").strip()
            presentacion = request.form.get("presentacion", "").strip()
            unidad_medida = request.form.get("unidad_medida", "").strip()
            stock_texto = request.form.get("stock", "").strip()
            estado = 1 if request.form.get("estado") == "1" else 0

            if not nombre:
                return render_template(
                    "medicamento_formulario.html",
                    medicamento=request.form,
                    error="El nombre del medicamento es obligatorio."
                )

            try:
                stock = int(stock_texto)
                if stock < 0:
                    raise ValueError
            except ValueError:
                return render_template(
                    "medicamento_formulario.html",
                    medicamento=request.form,
                    error="Las existencias deben ser un número entero igual o mayor que cero."
                )

            cursor.execute("""
                UPDATE medicamentos
                SET nombre = %s,
                    descripcion = %s,
                    presentacion = %s,
                    unidad_medida = %s,
                    stock = %s,
                    estado = %s
                WHERE id_medicamento = %s
            """, (
                nombre,
                descripcion or None,
                presentacion or None,
                unidad_medida or None,
                stock,
                estado,
                id_medicamento
            ))

            conexion.commit()

            return redirect(url_for(
                "medicamentos",
                mensaje="actualizado"
            ))

        return render_template(
            "medicamento_formulario.html",
            medicamento=medicamento,
            error=""
        )
    finally:
        cursor.close()
        conexion.close()

# ==========================================
# MODULO DE HISTORIAL MEDICO
# ==========================================

@app.route("/historial-medico")
@requiere_rol("Administrador", "Medico", "Enfermero")
def historial_medico():
    busqueda = request.args.get("busqueda", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        
        cursor.execute("""
            SELECT
                i.id_interno,
                i.nombres,
                i.apellidos,
                i.fecha_nacimiento,
                i.estado
            FROM internos i
            WHERE (
                CONCAT(i.nombres, ' ', i.apellidos) LIKE %s
                OR i.nombres LIKE %s
                OR i.apellidos LIKE %s
            )
            ORDER BY i.apellidos, i.nombres
        """, (
            f"%{busqueda}%",
            f"%{busqueda}%",
            f"%{busqueda}%"
        ))


        residentes = cursor.fetchall()

        return render_template(
            "historial_medico.html",
            residentes=residentes,
            busqueda=busqueda
        )
    finally:
        cursor.close()
        conexion.close()

# ==========================================
# DETALLE DEL HISTORIAL MEDICO
# ==========================================

@app.route("/historial-medico/<int:id_interno>")
@requiere_rol("Administrador", "Medico", "Enfermero")
def detalle_historial_medico(id_interno):
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id_interno,
                nombres,
                apellidos,
                fecha_nacimiento,
                fecha_ingreso,
                diagnostico_ingreso,
                medicamentos_cajon,
                observaciones,
                estado
            FROM internos
            WHERE id_interno = %s
        """, (id_interno,))

        residente = cursor.fetchone()

        if not residente:
            return redirect(url_for("historial_medico"))

        cursor.execute("""
            SELECT
                id_historial,
                fecha_registro,
                tipo_condicion,
                descripcion,
                observaciones
            FROM historial_medico
            WHERE id_interno = %s
            ORDER BY fecha_registro DESC, id_historial DESC
        """, (id_interno,))

        antecedentes = cursor.fetchall()

        cursor.execute("""
            SELECT
                vm.id_visita,
                vm.fecha_visita,
                vm.motivo_visita,
                vm.diagnostico,
                vm.observaciones_medicas,
                CONCAT(m.nombres, ' ', m.apellidos) AS medico
            FROM visitas_medicas vm
            INNER JOIN medicos m
                ON vm.id_medico = m.id_medico
            WHERE vm.id_interno = %s
            ORDER BY vm.fecha_visita DESC
        """, (id_interno,))

        visitas = cursor.fetchall()

        return render_template(
            "detalle_historial_medico.html",
            residente=residente,
            antecedentes=antecedentes,
            visitas=visitas
        )
    finally:
        cursor.close()
        conexion.close()

# ==========================================
# REGISTRAR ANTECEDENTE MEDICO
# ==========================================

@app.route(
    "/historial-medico/<int:id_interno>/nuevo-antecedente",
    methods=["GET", "POST"]
)
@requiere_rol("Administrador", "Medico")
def nuevo_antecedente_medico(id_interno):
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id_interno, nombres, apellidos
            FROM internos
            WHERE id_interno = %s
        """, (id_interno,))

        residente = cursor.fetchone()

        if not residente:
            return redirect(url_for("historial_medico"))

        if request.method == "POST":
            fecha_registro = request.form.get(
                "fecha_registro", ""
            ).strip()

            tipo_condicion = request.form.get(
                "tipo_condicion", ""
            ).strip()

            descripcion = request.form.get(
                "descripcion", ""
            ).strip()

            observaciones = request.form.get(
                "observaciones", ""
            ).strip()

            if not fecha_registro or not descripcion:
                return render_template(
                    "antecedente_formulario.html",
                    residente=residente,
                    error="La fecha y la descripción son obligatorias.",
                    datos=request.form
                )

            cursor.execute("""
                INSERT INTO historial_medico (
                    id_interno,
                    fecha_registro,
                    tipo_condicion,
                    descripcion,
                    observaciones
                )
                VALUES (%s, %s, %s, %s, %s)
            """, (
                id_interno,
                fecha_registro,
                tipo_condicion or None,
                descripcion,
                observaciones or None
            ))

            conexion.commit()

            return redirect(
                url_for(
                    "detalle_historial_medico",
                    id_interno=id_interno
                )
            )

        return render_template(
            "antecedente_formulario.html",
            residente=residente,
            error=None,
            datos={}
        )

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# MÓDULO LABORATORIO: CATÁLOGO DE EXÁMENES
# =========================================================

@app.route("/laboratorio")
@requiere_rol("Administrador", "Medico", "Enfermero")
def laboratorio():
    busqueda = request.args.get("busqueda", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        consulta = """
            SELECT
                id_examen,
                nombre,
                descripcion,
                precio,
                estado
            FROM examenes_laboratorio
            WHERE (
                nombre LIKE %s
                OR descripcion LIKE %s
            )
            ORDER BY nombre
        """

        parametro = f"%{busqueda}%"
        cursor.execute(consulta, (parametro, parametro))
        examenes = cursor.fetchall()

        return render_template(
            "laboratorio.html",
            examenes=examenes,
            busqueda=busqueda
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# REGISTRAR NUEVO EXAMEN DE LABORATORIO
# =========================================================

@app.route("/laboratorio/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador")
def nuevo_examen_laboratorio():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        precio_texto = request.form.get("precio", "").strip()
        estado = request.form.get("estado", "1")

        if not nombre:
            flash("El nombre del examen es obligatorio.", "error")
            return redirect(url_for("nuevo_examen_laboratorio"))

        if len(nombre) > 100 or len(descripcion) > 255:
            flash("El nombre o la descripción superan la longitud permitida.", "error")
            return redirect(url_for("nuevo_examen_laboratorio"))

        try:
            precio = float(precio_texto)

            if precio < 0 or not math.isfinite(precio):
                raise ValueError

            # Validar que el estado sea válido.
            if estado not in ("0", "1"):
                raise ValueError

        except (ValueError, TypeError):
            flash("Ingresa un precio válido y un estado correcto.", "error")
            return redirect(url_for("nuevo_examen_laboratorio"))

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            consulta = """
                INSERT INTO examenes_laboratorio
                    (nombre, descripcion, precio, estado)
                VALUES (%s, %s, %s, %s)
            """

            cursor.execute(
                consulta,
                (
                    nombre,
                    descripcion or None,
                    precio,
                    int(estado)
                )
            )

            conexion.commit()
            flash("El examen se registró correctamente.", "success")
            return redirect(url_for("laboratorio"))

        except mysql.connector.IntegrityError:
            conexion.rollback()
            flash("Ya existe un examen con ese nombre.", "error")

        except mysql.connector.Error:
            conexion.rollback()
            app.logger.exception("Error al registrar examen de laboratorio.")
            flash("No fue posible registrar el examen. Intenta nuevamente.", "error")

        finally:
            cursor.close()
            conexion.close()

    return render_template("nuevo_examen_laboratorio.html")

# EDITAR EXAMEN DE LABORATORIO
@app.route("/laboratorio/editar/<int:id_examen>", methods=["GET", "POST"])
@requiere_rol("Administrador")
def editar_examen_laboratorio(id_examen):
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        if request.method == "POST":
            nombre = request.form.get("nombre", "").strip()
            descripcion = request.form.get("descripcion", "").strip()
            precio_texto = request.form.get("precio", "").strip()
            estado = request.form.get("estado", "1")

            if not nombre:
                flash("El nombre del examen es obligatorio.", "error")
                return redirect(
                    url_for("editar_examen_laboratorio", id_examen=id_examen)
                )

            if len(nombre) > 100 or len(descripcion) > 255:
                flash("El nombre o la descripción superan la longitud permitida.", "error")
                return redirect(
                    url_for("editar_examen_laboratorio", id_examen=id_examen)
                )

            try:
                precio = float(precio_texto)

                if not math.isfinite(precio) or precio < 0:
                    raise ValueError

                if estado not in ("0", "1"):
                    raise ValueError

            except (ValueError, TypeError):
                flash("Ingresa un precio válido y un estado correcto.", "error")
                return redirect(
                    url_for("editar_examen_laboratorio", id_examen=id_examen)
                )

            consulta = """
                UPDATE examenes_laboratorio
                SET nombre = %s,
                    descripcion = %s,
                    precio = %s,
                    estado = %s
                WHERE id_examen = %s
            """

            try:
                cursor.execute(
                    consulta,
                    (nombre, descripcion or None, precio, int(estado), id_examen)
                )
                conexion.commit()

                flash("El examen se actualizó correctamente.", "success")
                return redirect(url_for("laboratorio"))

            except mysql.connector.IntegrityError:
                conexion.rollback()
                flash("Ya existe otro examen con ese nombre.", "error")

            except mysql.connector.Error:
                conexion.rollback()
                app.logger.exception("Error al editar examen de laboratorio.")
                flash("No fue posible actualizar el examen.", "error")

        cursor.execute(
            """
            SELECT id_examen, nombre, descripcion, precio, estado
            FROM examenes_laboratorio
            WHERE id_examen = %s
            """,
            (id_examen,)
        )
        examen = cursor.fetchone()

        if not examen:
            flash("El examen solicitado no existe.", "error")
            return redirect(url_for("laboratorio"))

        return render_template("editar_examen.html", examen=examen)

    finally:
        cursor.close()
        conexion.close()

# Registrar resultados de laboratorio

@app.route("/laboratorio/resultados/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador", "Medico", "Enfermero")
def nuevo_resultado_laboratorio():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        if request.method == "POST":
            id_visita = request.form.get("id_visita", "").strip()
            id_examen = request.form.get("id_examen", "").strip()
            resultado = request.form.get("resultado", "").strip()
            observaciones = request.form.get("observaciones", "").strip()

            if not id_visita.isdigit() or not id_examen.isdigit():
                flash("Selecciona una visita médica y un examen válidos.", "error")
                return redirect(url_for("nuevo_resultado_laboratorio"))

            if not resultado:
                flash("El resultado es obligatorio.", "error")
                return redirect(url_for("nuevo_resultado_laboratorio"))

            try:
                cursor.execute("""
                    SELECT id_visita
                    FROM visitas_medicas
                    WHERE id_visita = %s
                """, (int(id_visita),))
                visita = cursor.fetchone()

                cursor.execute("""
                    SELECT id_examen
                    FROM examenes_laboratorio
                    WHERE id_examen = %s AND estado = 1
                """, (int(id_examen),))
                examen = cursor.fetchone()

                if not visita or not examen:
                    flash("La visita o el examen no existe o no está disponible.", "error")
                    return redirect(url_for("nuevo_resultado_laboratorio"))

                cursor.execute("""
                    INSERT INTO resultados_examenes
                        (id_visita, id_examen, resultado, observaciones)
                    VALUES (%s, %s, %s, %s)
                """, (
                    int(id_visita),
                    int(id_examen),
                    resultado,
                    observaciones or None
                ))

                conexion.commit()
                flash("El resultado de laboratorio se registró correctamente.", "success")
                return redirect(url_for("laboratorio"))

            except mysql.connector.Error:
                conexion.rollback()
                app.logger.exception("Error al registrar resultado de laboratorio.")
                flash("No fue posible registrar el resultado.", "error")

        cursor.execute("""
            SELECT
                v.id_visita,
                v.fecha_visita,
                i.nombres,
                i.apellidos,
                m.nombres AS nombres_medico,
                m.apellidos AS apellidos_medico
            FROM visitas_medicas v
            INNER JOIN internos i ON v.id_interno = i.id_interno
            INNER JOIN medicos m ON v.id_medico = m.id_medico
            ORDER BY v.fecha_visita DESC
        """)
        visitas = cursor.fetchall()

        cursor.execute("""
            SELECT id_examen, nombre, precio
            FROM examenes_laboratorio
            WHERE estado = 1
            ORDER BY nombre
        """)
        examenes = cursor.fetchall()

        return render_template(
            "nuevo_resultado_laboratorio.html",
            visitas=visitas,
            examenes=examenes
        )

    finally:
        cursor.close()
        conexion.close()

# Consultar resultados de laboratorio
@app.route("/laboratorio/resultados")
@requiere_rol("Administrador", "Medico", "Enfermero")
def resultados_laboratorio():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        consulta = """
            SELECT
                r.id_resultado,
                r.fecha_examen,
                r.resultado,
                r.observaciones,
                e.nombre AS nombre_examen,
                i.nombres AS nombres_interno,
                i.apellidos AS apellidos_interno,
                m.nombres AS nombres_medico,
                m.apellidos AS apellidos_medico
            FROM resultados_examenes r
            INNER JOIN examenes_laboratorio e
                ON r.id_examen = e.id_examen
            INNER JOIN visitas_medicas v
                ON r.id_visita = v.id_visita
            INNER JOIN internos i
                ON v.id_interno = i.id_interno
            INNER JOIN medicos m
                ON v.id_medico = m.id_medico
            ORDER BY r.fecha_examen DESC
        """

        cursor.execute(consulta)
        resultados = cursor.fetchall()

        return render_template(
            "resultados_laboratorio.html",
            resultados=resultados
        )

    except mysql.connector.Error:
        app.logger.exception("Error al consultar resultados de laboratorio.")
        flash("No fue posible cargar los resultados de laboratorio.", "error")
        return redirect(url_for("laboratorio"))

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# MODULO DE FACTURACION Y FINANZAS
# =========================================================

@app.route("/finanzas")
@requiere_rol("Administrador", "Contador")
def finanzas():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                COALESCE((
                    SELECT SUM(monto)
                    FROM donaciones
                ), 0) AS total_donaciones,
                COALESCE((
                    SELECT SUM(monto)
                    FROM pagos_fundacion
                ), 0) AS total_pagos_fundacion,
                COALESCE((
                    SELECT SUM(monto)
                    FROM pagos_familiares
                ), 0) AS total_pagos_familiares,
                COALESCE((
                    SELECT SUM(monto)
                    FROM gastos
                ), 0) AS total_gastos
        """)

        resumen = cursor.fetchone()

        ingresos = (
            float(resumen["total_donaciones"])
            + float(resumen["total_pagos_fundacion"])
            + float(resumen["total_pagos_familiares"])
        )

        egresos = float(resumen["total_gastos"])

        resumen["total_ingresos"] = ingresos
        resumen["total_gastos"] = egresos
        resumen["balance"] = ingresos - egresos

        cursor.execute("""
            SELECT
                c.id_cuota,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.nombres,
                i.apellidos,
                COALESCE(SUM(p.monto), 0) AS total_pagado
            FROM cuotas_mensuales c
            INNER JOIN internos i
                ON i.id_interno = c.id_interno
            LEFT JOIN pagos_familiares p
                ON p.id_cuota = c.id_cuota
            GROUP BY
                c.id_cuota,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.nombres,
                i.apellidos
            ORDER BY c.fecha_inicio DESC
            LIMIT 10
        """)

        cuotas_recientes = cursor.fetchall()

        for cuota in cuotas_recientes:
            cuota["monto"] = float(cuota["monto"])
            cuota["total_pagado"] = float(cuota["total_pagado"])
            cuota["saldo"] = max(
                0,
                cuota["monto"] - cuota["total_pagado"]
            )

        return render_template(
            "finanzas.html",
            resumen=resumen,
            cuotas_recientes=cuotas_recientes
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# CONSULTAR PAGOS DE LA FUNDACION
# =========================================================

@app.route("/finanzas/pagos-fundacion")
@requiere_rol("Administrador", "Contador")
def finanzas_pagos_fundacion():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id_pago,
                fecha_pago,
                monto,
                concepto,
                referencia,
                observaciones
            FROM pagos_fundacion
            ORDER BY fecha_pago DESC
        """)

        pagos = cursor.fetchall()

        cursor.execute("""
            SELECT COALESCE(SUM(monto), 0) AS total
            FROM pagos_fundacion
        """)

        resultado = cursor.fetchone()
        total = float(resultado["total"])

        for pago in pagos:
            pago["monto"] = float(pago["monto"])

        return render_template(
            "finanzas_pagos_fundacion.html",
            pagos=pagos,
            total=total
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# REGISTRAR PAGO DE LA FUNDACION
# =========================================================

@app.route("/finanzas/pagos-fundacion/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador", "Contador")
def finanzas_pago_fundacion_nuevo():
    if request.method == "POST":
        fecha_pago = request.form.get("fecha_pago", "").strip()
        monto_texto = request.form.get("monto", "").strip()
        concepto = request.form.get("concepto", "").strip()
        referencia = request.form.get("referencia", "").strip()
        observaciones = request.form.get("observaciones", "").strip()

        try:
            monto = float(monto_texto)

            if monto <= 0:
                raise ValueError

        except (ValueError, TypeError):
            return render_template(
                "finanzas_pago_fundacion_nuevo.html",
                error="Ingresa un monto válido mayor que cero.",
                datos=request.form
            )

        if not concepto:
            return render_template(
                "finanzas_pago_fundacion_nuevo.html",
                error="El concepto del pago es obligatorio.",
                datos=request.form
            )

        if fecha_pago:
            try:
                fecha_pago = datetime.strptime(
                    fecha_pago, "%Y-%m-%dT%H:%M"
                ).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return render_template(
                    "finanzas_pago_fundacion_nuevo.html",
                    error="La fecha del pago no es válida.",
                    datos=request.form
                )

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            if fecha_pago:
                cursor.execute("""
                    INSERT INTO pagos_fundacion (
                        fecha_pago,
                        monto,
                        concepto,
                        referencia,
                        observaciones
                    )
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    fecha_pago,
                    monto,
                    concepto,
                    referencia or None,
                    observaciones or None
                ))
            else:
                cursor.execute("""
                    INSERT INTO pagos_fundacion (
                        monto,
                        concepto,
                        referencia,
                        observaciones
                    )
                    VALUES (%s, %s, %s, %s)
                """, (
                    monto,
                    concepto,
                    referencia or None,
                    observaciones or None
                ))

            conexion.commit()

        except Exception:
            conexion.rollback()
            raise

        finally:
            cursor.close()
            conexion.close()

        return redirect(url_for("finanzas_pagos_fundacion"))

    return render_template(
        "finanzas_pago_fundacion_nuevo.html",
        error=None,
        datos={}
    )

# ---------------------------------------------------------
# CONSULTA DE CUOTAS MENSUALES Y SALDOS DE RESIDENTES
# ---------------------------------------------------------
@app.route("/finanzas/cuotas")
@requiere_rol("Administrador", "Contador")
def finanzas_cuotas():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                c.id_cuota,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.id_interno,
                i.nombres,
                i.apellidos,
                COALESCE(SUM(p.monto), 0) AS total_pagado
            FROM cuotas_mensuales c
            INNER JOIN internos i
                ON i.id_interno = c.id_interno
            LEFT JOIN pagos_familiares p
                ON p.id_cuota = c.id_cuota
            GROUP BY
                c.id_cuota,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.id_interno,
                i.nombres,
                i.apellidos
            ORDER BY c.fecha_inicio DESC
        """)

        cuotas = cursor.fetchall()

        for cuota in cuotas:
            cuota["monto"] = float(cuota["monto"])
            cuota["total_pagado"] = float(cuota["total_pagado"])
            cuota["saldo"] = max(
                0,
                cuota["monto"] - cuota["total_pagado"]
            )

        return render_template("finanzas_cuotas.html", cuotas=cuotas)

    finally:
        cursor.close()
        conexion.close()

# ---------------------------------------------------------
# REGISTRO DE CUOTAS MENSUALES DE RESIDENTES
# ---------------------------------------------------------
@app.route("/finanzas/cuotas/nueva", methods=["GET", "POST"])
@requiere_rol("Administrador", "Contador")
def finanzas_cuota_nueva():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id_interno, nombres, apellidos
            FROM internos
            WHERE estado = 'Activo'
            ORDER BY apellidos, nombres
        """)
        residentes = cursor.fetchall()

        if request.method == "POST":
            id_interno = request.form.get("id_interno", "").strip()
            fecha_inicio = request.form.get("fecha_inicio", "").strip()
            fecha_fin = request.form.get("fecha_fin", "").strip()
            monto = request.form.get("monto", "").strip()

            try:
                id_interno = int(id_interno)
                fecha_inicio_valida = datetime.strptime(
                    fecha_inicio, "%Y-%m-%d"
                ).date()
                fecha_fin_valida = datetime.strptime(
                    fecha_fin, "%Y-%m-%d"
                ).date()
                monto_valido = float(monto)

                if monto_valido <= 0:
                    raise ValueError

                if fecha_fin_valida < fecha_inicio_valida:
                    flash(
                        "La fecha final no puede ser anterior a la inicial.",
                        "error"
                    )
                    return render_template(
                        "finanzas_cuota_nueva.html",
                        residentes=residentes
                    )

                cursor.execute("""
                    SELECT id_interno
                    FROM internos
                    WHERE id_interno = %s AND estado = 'Activo'
                """, (id_interno,))

                if not cursor.fetchone():
                    flash("Selecciona un residente activo válido.", "error")
                    return render_template(
                        "finanzas_cuota_nueva.html",
                        residentes=residentes
                    )

                cursor.execute("""
                    INSERT INTO cuotas_mensuales
                        (id_interno, fecha_inicio, fecha_fin, monto, estado)
                    VALUES (%s, %s, %s, %s, 'Pendiente')
                """, (
                    id_interno,
                    fecha_inicio_valida,
                    fecha_fin_valida,
                    monto_valido
                ))

                conexion.commit()

                flash("La cuota mensual se registró correctamente.", "success")
                return redirect(url_for("finanzas_cuotas"))

            except (ValueError, TypeError):
                flash(
                    "Verifica los datos. El monto debe ser mayor que cero "
                    "y las fechas deben ser válidas.",
                    "error"
                )

        return render_template(
            "finanzas_cuota_nueva.html",
            residentes=residentes
        )

    finally:
        cursor.close()
        conexion.close()

# ---------------------------------------------------------
# REGISTRO DE PAGOS FAMILIARES
# ---------------------------------------------------------
@app.route("/finanzas/cuotas/<int:id_cuota>/pago", methods=["GET", "POST"])
@requiere_rol("Administrador", "Contador")
def finanzas_registrar_pago(id_cuota):
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                c.id_cuota,
                c.id_interno,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.nombres,
                i.apellidos,
                COALESCE(SUM(p.monto), 0) AS total_pagado
            FROM cuotas_mensuales c
            INNER JOIN internos i
                ON i.id_interno = c.id_interno
            LEFT JOIN pagos_familiares p
                ON p.id_cuota = c.id_cuota
            WHERE c.id_cuota = %s
            GROUP BY
                c.id_cuota,
                c.id_interno,
                c.fecha_inicio,
                c.fecha_fin,
                c.monto,
                c.estado,
                i.nombres,
                i.apellidos
        """, (id_cuota,))

        cuota = cursor.fetchone()

        if not cuota:
            flash("La cuota solicitada no existe.", "error")
            return redirect(url_for("finanzas_cuotas"))

        cuota["monto"] = Decimal(str(cuota["monto"]))
        cuota["total_pagado"] = Decimal(str(cuota["total_pagado"]))
        cuota["saldo"] = max(
            Decimal("0.00"),
            cuota["monto"] - cuota["total_pagado"]
        )

        cursor.execute("""
            SELECT id_familiar, nombres, apellidos, parentesco,
                   responsable_pago
            FROM familiares
            WHERE id_interno = %s
            ORDER BY responsable_pago DESC, apellidos, nombres
        """, (cuota["id_interno"],))

        familiares = cursor.fetchall()

        if request.method == "POST":
            id_familiar = request.form.get("id_familiar", "").strip()
            monto_texto = request.form.get("monto", "").strip()
            metodo_pago = request.form.get("metodo_pago", "").strip()
            referencia = request.form.get("referencia", "").strip()
            observaciones = request.form.get("observaciones", "").strip()

            try:
                id_familiar = int(id_familiar)
                monto_pago = Decimal(monto_texto)

                if not monto_pago.is_finite() or monto_pago <= 0:
                    raise InvalidOperation

                if len(monto_pago.as_tuple().digits) > 12:
                    raise InvalidOperation

                if monto_pago.as_tuple().exponent < -2:
                    raise InvalidOperation

                metodos_validos = {
                    "Efectivo",
                    "Transferencia",
                    "Tarjeta",
                    "Depósito",
                    "Otro"
                }

                if metodo_pago not in metodos_validos:
                    flash("Selecciona un método de pago válido.", "error")
                    return render_template(
                        "finanzas_pago_nuevo.html",
                        cuota=cuota,
                        familiares=familiares
                    )

                cursor.execute("""
                    SELECT id_familiar
                    FROM familiares
                    WHERE id_familiar = %s AND id_interno = %s
                """, (id_familiar, cuota["id_interno"]))

                if not cursor.fetchone():
                    flash(
                        "Selecciona un familiar del residente correspondiente.",
                        "error"
                    )
                    return render_template(
                        "finanzas_pago_nuevo.html",
                        cuota=cuota,
                        familiares=familiares
                    )

                if monto_pago > cuota["saldo"]:
                    flash(
                        "El pago no puede ser mayor que el saldo pendiente.",
                        "error"
                    )
                    return render_template(
                        "finanzas_pago_nuevo.html",
                        cuota=cuota,
                        familiares=familiares
                    )

                if cuota["saldo"] <= 0:
                    flash("Esta cuota ya está pagada por completo.", "error")
                    return redirect(url_for("finanzas_cuotas"))

                cursor.execute("""
                    INSERT INTO pagos_familiares
                        (id_cuota, id_familiar, monto, metodo_pago,
                         referencia, observaciones)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    id_cuota,
                    id_familiar,
                    monto_pago,
                    metodo_pago,
                    referencia or None,
                    observaciones or None
                ))

                nuevo_total = cuota["total_pagado"] + monto_pago

                if nuevo_total >= cuota["monto"]:
                    nuevo_estado = "Pagada"
                else:
                    nuevo_estado = "Parcial"

                cursor.execute("""
                    UPDATE cuotas_mensuales
                    SET estado = %s
                    WHERE id_cuota = %s
                """, (nuevo_estado, id_cuota))

                conexion.commit()

                flash("El pago se registró correctamente.", "success")
                return redirect(url_for("finanzas_cuotas"))

            except (InvalidOperation, ValueError, TypeError):
                flash(
                    "Ingresa un monto válido con máximo dos decimales.",
                    "error"
                )

        return render_template(
            "finanzas_pago_nuevo.html",
            cuota=cuota,
            familiares=familiares
        )

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()
# ---------------------------------------------------------
# CONSULTA DE DONACIONES
# ---------------------------------------------------------
@app.route("/finanzas/donaciones")
@requiere_rol("Administrador", "Contador")
def finanzas_donaciones():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id_donacion,
                nombre_donante,
                tipo_donante,
                fecha_donacion,
                monto,
                descripcion,
                referencia
            FROM donaciones
            ORDER BY fecha_donacion DESC, id_donacion DESC
        """)

        donaciones = cursor.fetchall()

        total_donaciones = sum(
            (Decimal(str(d["monto"])) for d in donaciones),
            Decimal("0.00")
        )

        return render_template(
            "finanzas_donaciones.html",
            donaciones=donaciones,
            total_donaciones=total_donaciones
        )

    finally:
        cursor.close()
        conexion.close()

# ---------------------------------------------------------
# REGISTRO DE DONACIONES
# ---------------------------------------------------------
@app.route("/finanzas/donaciones/nueva", methods=["GET", "POST"])
@requiere_rol("Administrador", "Contador")
def finanzas_donacion_nueva():
    if request.method == "POST":
        nombre_donante = request.form.get("nombre_donante", "").strip()
        tipo_donante = request.form.get("tipo_donante", "").strip()
        fecha_texto = request.form.get("fecha_donacion", "").strip()
        monto_texto = request.form.get("monto", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        referencia = request.form.get("referencia", "").strip()

        formulario = request.form

        try:
            if not nombre_donante or not tipo_donante:
                raise ValueError("Completa el nombre y el tipo de donante.")

            if len(nombre_donante) > 150:
                raise ValueError("El nombre del donante es demasiado largo.")

            fecha_donacion = datetime.strptime(
                fecha_texto, "%Y-%m-%d"
            ).date()

            monto = Decimal(monto_texto)

            if not monto.is_finite() or monto <= 0:
                raise ValueError("El monto debe ser mayor que cero.")

            if monto > Decimal("99999999.99"):
                raise ValueError("El monto supera el máximo permitido.")

            if monto.as_tuple().exponent < -2:
                raise ValueError("El monto admite un máximo de dos decimales.")

        except (ValueError, InvalidOperation):
            flash(
                "Verifica los datos. La fecha debe ser válida y el monto "
                "debe ser positivo, con un máximo de dos decimales.",
                "error"
            )

            return render_template(
                "finanzas_donacion_nueva.html",
                fecha_hoy=datetime.now().date().isoformat(),
                donacion=formulario
            )

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute("""
                INSERT INTO donaciones (
                    nombre_donante,
                    tipo_donante,
                    fecha_donacion,
                    monto,
                    descripcion,
                    referencia
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                nombre_donante,
                tipo_donante,
                fecha_donacion,
                monto,
                descripcion or None,
                referencia or None
            ))

            conexion.commit()

            flash("La donación se registró correctamente.", "success")

            return redirect(url_for("finanzas_donaciones"))

        except Exception:
            conexion.rollback()
            raise

        finally:
            cursor.close()
            conexion.close()

    return render_template(
        "finanzas_donacion_nueva.html",
        fecha_hoy=datetime.now().date().isoformat(),
        donacion={}
    )

# ---------------------------------------------------------
# CONSULTA DE GASTOS
# ---------------------------------------------------------
@app.route("/finanzas/gastos")
@requiere_rol("Administrador", "Contador")
def finanzas_gastos():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id_gasto,
                fecha_gasto,
                categoria,
                descripcion,
                monto,
                proveedor,
                referencia,
                observaciones
            FROM gastos
            ORDER BY fecha_gasto DESC, id_gasto DESC
        """)

        gastos = cursor.fetchall()

        total_gastos = sum(
            (Decimal(str(g["monto"])) for g in gastos),
            Decimal("0.00")
        )

        return render_template(
            "finanzas_gastos.html",
            gastos=gastos,
            total_gastos=total_gastos
        )

    finally:
        cursor.close()
        conexion.close()

# ---------------------------------------------------------
# REGISTRO DE GASTOS
# ---------------------------------------------------------
@app.route("/finanzas/gastos/nuevo", methods=["GET", "POST"])
@requiere_rol("Administrador", "Contador")
def finanzas_gasto_nuevo():
    categorias = [
        "Alimentación",
        "Medicamentos",
        "Servicios básicos",
        "Personal",
        "Mantenimiento",
        "Limpieza",
        "Equipamiento",
        "Otros"
    ]

    if request.method == "POST":
        fecha_texto = request.form.get("fecha_gasto", "").strip()
        categoria = request.form.get("categoria", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        monto_texto = request.form.get("monto", "").strip()
        proveedor = request.form.get("proveedor", "").strip()
        referencia = request.form.get("referencia", "").strip()
        observaciones = request.form.get("observaciones", "").strip()

        formulario = request.form

        try:
            if categoria not in categorias:
                raise ValueError("Selecciona una categoría válida.")

            if not descripcion:
                raise ValueError("La descripción es obligatoria.")

            fecha_gasto = datetime.strptime(
                fecha_texto, "%Y-%m-%d"
            ).date()

            monto = Decimal(monto_texto)

            if not monto.is_finite() or monto <= 0:
                raise ValueError("El monto debe ser mayor que cero.")

            if monto > Decimal("99999999.99"):
                raise ValueError("El monto supera el máximo permitido.")

            if monto.as_tuple().exponent < -2:
                raise ValueError("El monto admite máximo dos decimales.")

        except (ValueError, InvalidOperation):
            flash(
                "Verifica la fecha, categoría, descripción y monto.",
                "error"
            )

            return render_template(
                "finanzas_gasto_nuevo.html",
                categorias=categorias,
                fecha_hoy=datetime.now().date().isoformat(),
                gasto=formulario
            )

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute("""
                INSERT INTO gastos (
                    fecha_gasto,
                    categoria,
                    descripcion,
                    monto,
                    proveedor,
                    referencia,
                    observaciones
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                fecha_gasto,
                categoria,
                descripcion,
                monto,
                proveedor or None,
                referencia or None,
                observaciones or None
            ))

            conexion.commit()

            flash("El gasto se registró correctamente.", "success")

            return redirect(url_for("finanzas_gastos"))

        except Exception:
            conexion.rollback()
            raise

        finally:
            cursor.close()
            conexion.close()

    return render_template(
        "finanzas_gasto_nuevo.html",
        categorias=categorias,
        fecha_hoy=datetime.now().date().isoformat(),
        gasto={}
    )

# =========================================================
# MODULO DE REPORTES FINANCIEROS
# =========================================================

@app.route("/reportes")
@requiere_rol("Administrador", "Contador")
def reportes():
    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    hoy = datetime.now().date()
    primer_dia_mes = hoy.replace(day=1)

    fecha_inicio_texto = request.args.get(
        "fecha_inicio", primer_dia_mes.isoformat()
    )
    fecha_fin_texto = request.args.get(
        "fecha_fin", hoy.isoformat()
    )

    error = None
    movimientos = []

    try:
        try:
            fecha_inicio = datetime.strptime(
                fecha_inicio_texto, "%Y-%m-%d"
            ).date()
            fecha_fin = datetime.strptime(
                fecha_fin_texto, "%Y-%m-%d"
            ).date()

            if fecha_inicio > fecha_fin:
                raise ValueError

        except ValueError:
            error = "Selecciona un periodo válido. La fecha inicial no puede ser posterior a la fecha final."
            fecha_inicio = primer_dia_mes
            fecha_fin = hoy
            fecha_inicio_texto = fecha_inicio.isoformat()
            fecha_fin_texto = fecha_fin.isoformat()

        if not error:
            # DONACIONES
            cursor.execute("""
                SELECT
                    fecha_donacion AS fecha,
                    monto,
                    CONCAT('Donación: ', nombre_donante) AS concepto,
                    COALESCE(descripcion, '') AS detalle,
                    COALESCE(referencia, '') AS referencia
                FROM donaciones
                WHERE fecha_donacion BETWEEN %s AND %s
            """, (fecha_inicio, fecha_fin))

            donaciones = cursor.fetchall()

            # PAGOS FAMILIARES
            cursor.execute("""
                SELECT
                    fecha_pago AS fecha,
                    monto,
                    'Pago familiar' AS concepto,
                    metodo_pago AS detalle,
                    COALESCE(referencia, '') AS referencia
                FROM pagos_familiares
                WHERE DATE(fecha_pago) BETWEEN %s AND %s
            """, (fecha_inicio, fecha_fin))

            pagos_familiares = cursor.fetchall()

            # PAGOS DE LA FUNDACION
            cursor.execute("""
                SELECT
                    fecha_pago AS fecha,
                    monto,
                    concepto,
                    COALESCE(observaciones, '') AS detalle,
                    COALESCE(referencia, '') AS referencia
                FROM pagos_fundacion
                WHERE DATE(fecha_pago) BETWEEN %s AND %s
            """, (fecha_inicio, fecha_fin))

            pagos_fundacion = cursor.fetchall()

            # GASTOS
            cursor.execute("""
                SELECT
                    fecha_gasto AS fecha,
                    monto,
                    CONCAT('Gasto: ', categoria) AS concepto,
                    CONCAT(
                        descripcion,
                        CASE
                            WHEN proveedor IS NOT NULL
                                AND proveedor <> ''
                            THEN CONCAT(' - Proveedor: ', proveedor)
                            ELSE ''
                        END
                    ) AS detalle,
                    COALESCE(referencia, '') AS referencia
                FROM gastos
                WHERE fecha_gasto BETWEEN %s AND %s
            """, (fecha_inicio, fecha_fin))

            gastos = cursor.fetchall()

            # CALCULAR LOS TOTALES DEL PERIODO
            from decimal import Decimal

            total_donaciones = sum(
                (p["monto"] for p in donaciones),
                Decimal("0.00")
            )

            total_pagos_familiares = sum(
                (p["monto"] for p in pagos_familiares),
                Decimal("0.00")
            )

            total_pagos_fundacion = sum(
                (p["monto"] for p in pagos_fundacion),
                Decimal("0.00")
            )

            total_gastos = sum(
                (p["monto"] for p in gastos),
                Decimal("0.00")
            )

            total_ingresos = (
                total_donaciones
                + total_pagos_familiares
                + total_pagos_fundacion
            )

            balance = total_ingresos - total_gastos

            # UNIFICAR LOS MOVIMIENTOS PARA MOSTRARLOS EN UNA TABLA
            for tipo, registros in [
                ("Donación", donaciones),
                ("Pago familiar", pagos_familiares),
                ("Pago de la fundación", pagos_fundacion),
                ("Gasto", gastos)
            ]:
                for registro in registros:
                    fecha = registro["fecha"]

                    if isinstance(fecha, datetime):
                        fecha = fecha.date()

                    movimientos.append({
                        "fecha": fecha,
                        "tipo": tipo,
                        "concepto": registro["concepto"],
                        "detalle": registro["detalle"],
                        "referencia": registro["referencia"],
                        "monto": registro["monto"],
                        "es_gasto": tipo == "Gasto"
                    })

            movimientos.sort(
                key=lambda movimiento: movimiento["fecha"],
                reverse=True
            )

        else:
            total_donaciones = Decimal("0.00")
            total_pagos_familiares = Decimal("0.00")
            total_pagos_fundacion = Decimal("0.00")
            total_gastos = Decimal("0.00")
            total_ingresos = Decimal("0.00")
            balance = Decimal("0.00")

        return render_template(
            "reportes.html",
            fecha_inicio=fecha_inicio_texto,
            fecha_fin=fecha_fin_texto,
            error=error,
            movimientos=movimientos,
            total_donaciones=total_donaciones,
            total_pagos_familiares=total_pagos_familiares,
            total_pagos_fundacion=total_pagos_fundacion,
            total_ingresos=total_ingresos,
            total_gastos=total_gastos,
            balance=balance
        )

    finally:
        cursor.close()
        conexion.close()

# =========================================================
# CERRAR SESIÓN
# =========================================================

@app.route("/cerrar-sesion")
def cerrar_sesion():

    session.clear()

    return redirect(url_for("login"))

# =========================================================
# EJECUTAR APLICACIÓN
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)