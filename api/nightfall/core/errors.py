from fastapi import HTTPException


def api_error(status: int, code: str, message: str) -> HTTPException:
    """Uniform error body: {"detail": {"code": ..., "message": ...}}."""
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def not_found(what: str = "Not found") -> HTTPException:
    return api_error(404, "not_found", what)
