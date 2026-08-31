import re

with open('relay/wazuh_waha/api/dashboard.py', 'r') as f:
    content = f.read()

endpoint = """
@router.get("/api/v1/dashboard/wazuh/agents")
async def get_wazuh_agents(request: Request, _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    if not settings.wazuh_manager_host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada (faltan credenciales)"}

    base = f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh Manager API"}
            
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/agents", headers=headers)
            
            if r.is_success:
                data = r.json()
                agents = data.get("data", {}).get("affected_items", [])
                return {"agents": agents}
            else:
                return {"error": f"Error de Wazuh API: {r.status_code} {r.text[:100]}"}
    except Exception as e:
        return {"error": str(e)}

"""

if "get_wazuh_agents" not in content:
    content += "\n" + endpoint

with open('relay/wazuh_waha/api/dashboard.py', 'w') as f:
    f.write(content)
