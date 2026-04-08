import logging

import httpx
from openai import OpenAI

from backend.app.config import settings

logger = logging.getLogger(__name__)


class LMStudioClient:
    def __init__(self) -> None:
        self._client = OpenAI(
            base_url=settings.lm_studio_base_url,
            api_key="lm-studio",
            timeout=httpx.Timeout(120.0, connect=10.0),
            max_retries=0,
        )
        self._model = settings.lm_studio_model

    def analyze(self, user_prompt: str, system_prompt: str) -> dict:
        """Send a chat completion request and return the parsed result.

        Returns a dict with 'content', 'usage', and 'model' keys.
        """
        logger.info("Sending analysis request to LM Studio (model=%s)", self._model)

        # LM Studio rejects OpenAI's response_format.type "json_object" (400: must be
        # "json_schema" or "text"). We rely on the prompt for JSON; parse_llm_response
        # accepts raw JSON or ```json``` fences.
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
        )

        choice = response.choices[0]
        usage = response.usage

        return {
            "content": choice.message.content or "",
            "model": response.model,
            "prompt_tokens": usage.prompt_tokens if usage else None,
            "completion_tokens": usage.completion_tokens if usage else None,
        }


lm_studio_client = LMStudioClient()
