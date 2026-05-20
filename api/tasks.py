"""
Celery 분석 태스크 (api/tasks.py)

분석 파이프라인을 Celery task로 래핑합니다.
실제 로직은 analyzer.pipeline.execute_pipeline()에 위임합니다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.celery_app import celery_app


@celery_app.task(bind=True, name="dallo.analyze")
def run_analysis_task(self, code: str, filename: str, use_llm: bool = True,
                      provider: str = "gateway", model: str = "claude-sonnet-4-6",
                      multi_patch: bool = False,
                      cve_scope: list[str] | None = None,
                      cwe_scope: list[str] | None = None,
                      rule_scope: list[str] | None = None,
                      max_llm_targets: int | None = None,
                      max_context_chars: int | None = None,
                      batch_llm: bool | None = None,
                      llm_audit_when_clean: bool = False,
                      user_prompt: str | None = None):
    """
    Celery task: 분석 파이프라인 실행

    self.update_state()를 통해 진행 상태를 Redis에 기록합니다.
    실제 분석 로직은 analyzer.pipeline에 위임합니다.
    """
    from analyzer.pipeline import execute_pipeline

    job_id = self.request.id

    def on_progress(step: str):
        self.update_state(state="PROGRESS", meta={"step": step, "job_id": job_id})

    try:
        result = execute_pipeline(
            job_id=job_id, code=code, filename=filename,
            use_llm=use_llm, provider=provider, model=model,
            multi_patch=multi_patch,
            cve_scope=cve_scope,
            cwe_scope=cwe_scope,
            rule_scope=rule_scope,
            max_llm_targets=max_llm_targets,
            max_context_chars=max_context_chars,
            batch_llm=batch_llm,
            llm_audit_when_clean=llm_audit_when_clean,
            user_prompt=user_prompt,
            on_progress=on_progress,
        )

        return {
            "status": "completed",
            "result": result.result_data,
            "job_id": job_id,
        }

    except ValueError as e:
        return {"status": "failed", "error": str(e), "job_id": job_id}
    except Exception as e:
        return {"status": "failed", "error": str(e), "job_id": job_id}
