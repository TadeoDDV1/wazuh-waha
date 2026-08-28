import sys

def modify_dashboard(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    # 1. Add base64 import after httpx import
    for i, line in enumerate(lines):
        if 'import httpx' in line:
            lines.insert(i + 1, 'import base64\n')
            break

    # 2. Add waha_qr component after waha_session component
    for i, line in enumerate(lines):
        if '"actions": ["start", "stop"],' in line:
            # Find the closing brace of this component
            for j in range(i, len(lines)):
                if lines[j].strip() == '},':
                    # Insert after this line
                    new_component = [
                        '    {\n',
                        '        "id": "waha_qr",\n',
                        '        "name": "Código QR de WhatsApp",\n',
                        '        "category": "whatsapp",\n',
                        '        "icon": "📱",\n',
                        '        "description": "Escanea este código con WhatsApp para vincular tu sesión a WAHA",\n',
                        '        "status_type": "waha_qr",  # Nuevo tipo especial\n',
                        '        "toggleable": False,\n',
                        '        "actions": ["refresh"],  # Para forzar regeneración si es necesario\n',
                        '    },\n'
                    ]
                    for k, new_line in enumerate(new_component):
                        lines.insert(j + 1 + k, new_line)
                    break
            break

    # 3. Add _check_waha_qr function before _boot_time function
    for i, line in enumerate(lines):
        if 'def _boot_time()' in line:
            qr_function = [
                '\n',
                'async def _check_waha_qr() -> tuple[str, str, dict]:\n',
                '    """Obtiene estado y datos del código QR WAHA."""\n',
                '    if not settings.waha_host:\n',
                '        return "disabled", "WAHA_HOST vacío", {}\n',
                '    \n',
                '    try:\n',
                '        async with httpx.AsyncClient(timeout=10) as client:\n',
                '            r = await client.get(\n',
                '                f"{settings.waha_host}/api/sessions/{settings.waha_session}/qr",\n',
                '                headers={"X-Api-Key": settings.waha_api_key},\n',
                '            )\n',
                '            \n',
                '            if r.is_success:\n',
                '                # Determinar estado basado en sesión\n',
                '                session_r = await client.get(\n',
                '                    f"{settings.waha_host}/api/sessions/{settings.waha_session}",\n',
                '                    headers={"X-Api-Key": settings.waha_api_key},\n',
                '                )\n',
                '                session_data = session_r.json() if session_r.is_success else {}\n',
                '                session_status = session_data.get("status", "unknown")\n',
                '                \n',
                '                if session_status == "WORKING":\n',
                '                    return "healthy", "Sesión activa (QR no necesario)", {"qr": None}\n',
                '                elif session_status in ("STARTING", "SCANNING_QR"):\n',
                '                    # Devolver QR como base64 para embedding directo en HTML\n',
                '                    b64qr = base64.b64encode(r.content).decode(\'utf-8\')\n',
                '                    content_type = r.headers.get("content-type", "image/png")\n',
                '                    data_url = f"data:{content_type};base64,{b64qr}"\n',
                '                    return "warning", "Escanea el QR para vincular sesión", {"qr": data_url}\n',
                '                else:\n',
                '                    return "error", f"Sesión en estado inesperado: {session_status}", {"qr": None}\n',
                '            elif r.status_code == 404:\n',
                '                return "error", "Endpoint QR no disponible en esta versión de WAHA", {}\n',
                '            else:\n',
                '                return "error", f"Error WAHA: HTTP {r.status_code}", {}\n',
                '    except httpx.ConnectError:\n',
                '        return "error", "WAHA no accesible", {}\n',
                '    except Exception as e:\n',
                '        return "error", str(e)[:100], {}\n',
                '\n'
            ]
            for k, new_line in enumerate(qr_function):
                lines.insert(i + k, new_line)
            break

    # 4. Update gather_status to handle waha_qr
    for i, line in enumerate(lines):
        if '# Check WAHA session is async (httpx); everything else is sync' in line:
            # Find the if-else block and insert elif
            for j in range(i, len(lines)):
                if 'else:' in lines[j] and lines[j].strip().startswith('else:'):
                    # Insert elif before this else
                    new_block = [
                        '        elif comp["status_type"] == "waha_qr":\n',
                        '            wq_health, wq_detail, wq_extra = await _check_waha_qr()\n',
                        '            result = {\n',
                        '                "id": comp["id"],\n',
                        '                "name": comp["name"],\n',
                        '                "category": comp["category"],\n',
                        '                "icon": comp["icon"],\n',
                        '                "description": comp["description"],\n',
                        '                "health": wq_health,\n',
                        '                "detail": wq_detail,\n',
                        '                "toggleable": comp["toggleable"],\n',
                        '                "current_state": wq_health in ("healthy", "warning"),\n',
                        '                "actions": comp["actions"],\n',
                        '                "unit": comp.get("unit", ""),\n',
                        '                "qr_data": wq_extra.get("qr") if "qr" in wq_extra else None\n',
                        '            }\n',
                        '            results.append(result)\n',
                    ]
                    for k, new_line in enumerate(new_block):
                        lines.insert(j + k, new_line)
                    break
            break

    # 5. Add the QR endpoint after dashboard_config function
    for i, line in enumerate(lines):
        if '@router.get("/api/v1/dashboard/config", response_class=JSONResponse)' in line:
            # Find the end of the function
            for j in range(i, len(lines)):
                if lines[j].strip() == '}' and j > i:
                    # Check if this is the end of the function (next line is not indented or is a new decorator)
                    if j + 1 < len(lines) and not lines[j + 1].startswith('    ') and lines[j + 1].strip() != '':
                        new_endpoint = [
                            '\n',
                            '@router.get("/api/v1/dashboard/qr", response_class=Response)\n',
                            'async def dashboard_qr(request: Request):\n',
                            '    """Obtiene código QR para sesión WAHA actual."""\n',
                            '    await verify_api_key(request)\n',
                            '\n',
                            '    if not settings.waha_host:\n',
                            '        raise HTTPException(status_code=400, detail="WAHA_HOST no configurado")\n',
                            '\n',
                            '    try:\n',
                            '        async with httpx.AsyncClient(timeout=10) as client:\n',
                            '            r = await client.get(\n',
                            '                f"{settings.waha_host}/api/sessions/{settings.waha_session}/qr",\n',
                            '                headers={"X-Api-Key": settings.waha_api_key},\n',
                            '            )\n',
                            '\n',
                            '            if r.is_success:\n',
                            '                # Determinar tipo de contenido\n',
                            '                content_type = r.headers.get("content-type", "image/png")\n',
                            '                return Response(content=r.content, media_type=content_type)\n',
                            '            else:\n',
                            '                raise HTTPException(\n',
                            '                    status_code=r.status_code,\n',
                            '                    detail=f"WAHA error: {r.text}"\n',
                            '                )\n',
                            '    except httpx.ConnectError:\n',
                            '        raise HTTPException(status_code=503, detail="WAHA no accesible")\n',
                            '    except Exception as e:\n',
                            '        raise HTTPException(status_code=500, detail=str(e))\n',
                            '\n'
                        ]
                        for k, new_line in enumerate(new_endpoint):
                            lines.insert(j + 1 + k, new_line)
                        break
            break

    # 5. Replace _toggle_waha_session function
    for i, line in enumerate(lines):
        if 'def _toggle_waha_session(start: bool) -> tuple[bool, str]:' in line:
            # Find end of function
            for j in range(i, len(lines)):
                if j > i and lines[j].strip() and not lines[j].startswith('    ') and not lines[j].startswith('\t'):
                    # Found next function or non-indented line
                    # Replace from i to j-1
                    new_func = [
                        'def _toggle_waha_session(start: bool) -> tuple[bool, str, dict]:\n',
                        '    """Inicia/detiene sesión WAHA y opcionalmente retorna info de QR."""\n',
                        '    action = "start" if start else "stop"\n',
                        '    url = f"{settings.waha_host}/api/sessions/{settings.waha_session}/{action}"\n',
                        '    try:\n',
                        '        r = subprocess.run(\n',
                        '            ["curl", "-sS", "-m", "15",\n',
                        '             "-H", f"X-Api-Key: {settings.waha_api_key}",\n',
                        '             "-X", "POST", url],\n',
                        '            capture_output=True, text=True, timeout=20,\n',
                        '        )\n',
                        '        if r.returncode == 0:\n',
                        '            # Si estamos iniciando sesión, intentar obtener QR inmediatamente\n',
                        '            if start:\n',
                        '                time.sleep(2)  # Dar tiempo para que WAHA genere QR\n',
                        '                try:\n',
                        '                    qr_r = subprocess.run(\n',
                        '                        ["curl", "-sS", "-m", "10",\n',
                        '                         "-H", f"X-Api-Key: {settings.waha_api_key}",\n',
                        '                         f"{settings.waha_host}/api/sessions/{settings.waha_session}/qr"],\n',
                        '                        capture_output=True, text=True, timeout=10,\n',
                        '                    )\n',
                        '                    if qr_r.returncode == 0 and qr_r.stdout:\n',
                        '                        # Devolver éxito + datos QR para que frontend los muestre\n',
                        '                        return True, f"sesión {action}ed, QR disponible", {"qr_available": True}\n',
                        '                except:\n',
                        '                    pass  # Si falla obtener QR, aún así fue exitoso iniciar sesión\n',
                        '            return True, f"sesión {action}ed", {}\n',
                        '        return False, r.stderr.strip()[:200], {}\n',
                        '    except Exception as e:\n',
                        '        return False, str(e)[:200], {}\n',
                        '\n'
                    ]
                    lines[i:j] = new_func
                    break
            break

    # 6. Update toggle endpoint for wazuh_rules
    for i, line in enumerate(lines):
        if 'elif stype == "wazuh_rules":' in line:
            # Find the return statement for this block
            for j in range(i, len(lines)):
                if 'return' in lines[j] and 'wazuh_rules' in lines[j]:
                    # Replace from i to j
                    new_block = [
                        '    elif stype == "wazuh_rules":\n',
                        '        # Implementar toggle de reglas Wazuh vía API de Manager\n',
                        '        if not settings.wazuh_manager_api_user or not settings.wazuh_manager_api_pass:\n',
                        '            return {"ok": False, "result": "Credenciales de Wazuh Manager no configuradas", "target": target, "enabled": enabled}\n',
                        '        \n',
                        '        # Mapeo de group_id a patrones en local_rules.xml\n',
                        '        group_patterns = {\n',
                        '            "auth_rules": r\'<group\\s+name=["\']authentication["\']\',\n',
                        '            "vuln_rules": r\'<group\\s+name=["\']vulnerability_detector["\']\',\n',
                        '            "waha_health_rules": r\'<group\\s+name=["\']waha_health["\']\',\n',
                        '        }\n',
                        '\n',
                        '        pattern = group_patterns.get(target)\n',
                        '        if not pattern:\n',
                        '            return {"ok": False, "result": f"Grupo de reglas desconocido: {target}", "target": target, "enabled": enabled}\n',
                        '\n',
                        '        try:\n',
                        '            # 1. Obtener archivo actual de reglas\n',
                        '            auth = (settings.wazuh_manager_api_user, settings.wazuh_manager_api_pass)\n',
                        '            verify = settings.wazuh_manager_api_verify_tls\n',
                        '            \n',
                        '            r = httpx.get(\n',
                        '                f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}/manager/configuration/files/local_rules.xml",\n',
                        '                auth=auth,\n',
                        '                verify=verify,\n',
                        '                timeout=10\n',
                        '            )\n',
                        '            if not r.is_success:\n',
                        '                return {"ok": False, "result": f"Error al obtener reglas: HTTP {r.status_code}", "target": target, "enabled": enabled}\n',
                        '\n',
                        '            rules_content = r.text\n',
                        '\n',
                        '            # 2. Modificar contenido según acción enabled/disabled\n',
                        '            if enabled:\n',
                        '                # Activar: asegurar que el grupo no esté comentado\n',
                        '                # Buscamos el patrón y nos aseguramos de que no esté comentado\n',
                        '                import re\n',
                        '                modified_content = re.sub(rf"<!--\\s*({pattern}.*?)\\s*-->", r"\\1", rules_content, flags=re.DOTALL)\n',
                        '            else:\n',
                        '                # Desactivar: comentar el grupo\n',
                        '                import re\n',
                        '                modified_content = re.sub(rf"({pattern}.*?)</group>", r"<!-- \\1</group -->", rules_content, flags=re.DOTALL)\n',
                        '\n',
                        '            # 3. Enviar archivo modificado de vuelta\n',
                        '            r = httpx.put(\n',
                        '                f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}/manager/configuration/files/local_rules.xml",\n',
                        '                content=modified_content,\n',
                        '                auth=auth,\n',
                        '                verify=verify,\n',
                        '                headers={"Content-Type": "application/xml"},\n',
                        '                timeout=10\n',
                        '            )\n',
                        '\n',
                        '            if r.is_success:\n',
                        '                return {"ok": True, "result": f"Grupo \'{target}\' {\'activado\' if enabled else \'desactivado\'}", "target": target, "enabled": enabled}\n',
                        '            else:\n',
                        '                return {"ok": False, "result": f"Error al guardar reglas: HTTP {r.status_code}", "target": target, "enabled": enabled}\n',
                        '\n',
                        '        except httpx.RequestError as e:\n',
                        '            return {"ok": False, "result": f"Error de conexión a Wazuh Manager: {str(e)}", "target": target, "enabled": enabled}\n',
                        '        except Exception as e:\n',
                        '            return {"ok": False, "result": f"Error inesperado: {str(e)}", "target": target, "enabled": enabled}\n',
                    ]
                    lines[i:j+1] = new_block
                    break
            break

    # Write back
    with open(filepath, 'w') as f:
        f.writelines(lines)

if __name__ == '__main__':
    modify_dashboard(sys.argv[1])
