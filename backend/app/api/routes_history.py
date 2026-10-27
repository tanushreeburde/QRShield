from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from app.data.db import get_db
from app.data.models import ScanRecord, FindingRecord, RedirectHopRecord
from app.schemas.scan import HistoryResponse, ScanHistoryItem

router = APIRouter()


@router.get("/history", response_model=HistoryResponse)
async def get_scan_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    total_query = select(func.count(ScanRecord.id))
    total_res = await db.execute(total_query)
    total = total_res.scalar() or 0

    query = (
        select(ScanRecord)
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    records = result.scalars().all()

    items = []
    for rec in records:
        # Count findings and redirects
        f_count_res = await db.execute(
            select(func.count(FindingRecord.id)).where(FindingRecord.scan_id == rec.id)
        )
        r_count_res = await db.execute(
            select(func.count(RedirectHopRecord.id)).where(RedirectHopRecord.scan_id == rec.id)
        )

        items.append(ScanHistoryItem(
            id=rec.id,
            submitted_url=rec.submitted_url,
            final_url=rec.final_url,
            verdict=rec.verdict,
            score=rec.score,
            client_platform=rec.client_platform,
            created_at=rec.created_at,
            evidence_count=f_count_res.scalar() or 0,
            redirect_count=r_count_res.scalar() or 0
        ))

    return HistoryResponse(
        total=total,
        items=items,
        limit=limit,
        offset=offset
    )


@router.delete("/history/{scan_id}")
async def delete_history_record(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    # Check if record exists
    query = select(ScanRecord).where(ScanRecord.id == scan_id)
    res = await db.execute(query)
    record = res.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    await db.delete(record)
    await db.commit()

    return {"status": "deleted", "scan_id": scan_id}
