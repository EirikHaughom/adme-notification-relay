import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:  # pragma: no cover - trivial
    # Redirect from base /api to the osdu-relay endpoint
    location = "/api/osdu-relay"
    # 302 Found is fine for simple browser redirects; use 307 to preserve method if needed
    return func.HttpResponse(
        status_code=302,
        headers={"Location": location},
    )
