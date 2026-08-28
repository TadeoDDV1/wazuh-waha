from pydantic import BaseModel


class AlertMetadata(BaseModel):
    rule_id: str
    agent_id: str
    agent_name: str | None
    level: int
    decision: str
    ts: float


class FormatResult(BaseModel):
    message: str
    meta: AlertMetadata
