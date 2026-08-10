"""Canonical tests: LLM router — network boundary monkeypatched.

The HTTP layer (`_post`) is replaced; no live calls in tests. This exercises
route resolution, the deepseek-r1 DIRECT-Ollama pitfall fix, fallback chains,
and the async job queue.
"""

import unittest
from unittest.mock import patch

from intected import config, router
from intected.router import LocalJobQueue, Router, RouteError


def _fake_post(reply: str):
    """Build a _post stub that records (url, payload) and returns a completion."""
    calls = []

    def post(url, payload, timeout):
        calls.append((url, payload, timeout))
        return {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    return post, calls


class RouterResolveTest(unittest.TestCase):
    def test_reasoning_resolves_to_bridge_flash(self):
        r = Router().resolve("reasoning")
        self.assertEqual(r["model"], "deepseek-v4-flash")
        self.assertIn("11435", r["base_url"])

    def test_deep_reasoning_routes_to_direct_ollama(self):
        """PITFALL FIX: deepseek-r1:8b must hit :11434 DIRECT, never the bridge."""
        r = Router().resolve("deep_reasoning")
        self.assertEqual(r["model"], "deepseek-r1:8b")
        self.assertIn("11434", r["base_url"])
        self.assertNotIn("11435", r["base_url"])

    def test_local_routes_are_async_with_fallback(self):
        for cls in ("light", "extract_small", "code"):
            r = Router().resolve(cls)
            self.assertTrue(r["async"])
            self.assertEqual(r["fallback"], "reasoning")

    def test_unknown_class_raises(self):
        with self.assertRaises(KeyError):
            Router().resolve("nope")


class RouterChatTest(unittest.TestCase):
    def test_chat_calls_correct_endpoint(self):
        post, calls = _fake_post("OK")
        Router().chat("reasoning", [{"role": "user", "content": "hi"}], _post=post)
        url, payload, _ = calls[0]
        self.assertIn("11435", url)
        self.assertEqual(payload["model"], "deepseek-v4-flash")

    def test_chat_falls_back_to_flash_when_local_fails(self):
        """Local route error -> fallback to reasoning (flash)."""
        def flaky(url, payload, timeout):
            if "11435" not in url or payload["model"] != "deepseek-v4-flash":
                raise OSError("local model down")
            return {"choices": [{"message": {"role": "assistant", "content": "FLASH"}}]}

        out = Router().chat("light", [{"role": "user", "content": "x"}], _post=flaky)
        self.assertEqual(out, "FLASH")

    def test_no_fallback_raises_route_error(self):
        def boom(url, payload, timeout):
            raise TimeoutError("dead")

        with self.assertRaises(RouteError):
            Router().chat("reasoning", [{"role": "user", "content": "x"}], _post=boom)

    def test_reasoning_content_fallback(self):
        """deepseek-r1-style replies put text in reasoning_content."""
        def post(url, payload, timeout):
            return {"choices": [{"message": {
                "role": "assistant", "content": "",
                "reasoning_content": "thinking... ANSWER"}}]}

        out = Router().chat("deep_reasoning", [{"role": "user", "content": "x"}],
                            _post=post)
        self.assertIn("ANSWER", out)


class JobQueueTest(unittest.TestCase):
    def test_submit_poll_lifecycle(self):
        post, _ = _fake_post("DONE")
        q = LocalJobQueue(router=Router())
        # Patch the network boundary the worker thread calls (module global).
        with patch("intected.router._post_json", side_effect=post):
            job_id = q.submit("light", [{"role": "user", "content": "x"}])
            # Worker may finish before the first poll (fast stub) — accept
            # any intermediate state, then require terminal 'done'.
            self.assertIn(q.poll(job_id)["status"], ("queued", "running", "done"))
            import time
            deadline = time.time() + 15
            while time.time() < deadline:
                st = q.poll(job_id)["status"]
                if st in ("done", "error"):
                    break
                time.sleep(0.1)
        self.assertEqual(q.poll(job_id)["status"], "done")
        self.assertEqual(q.poll(job_id)["result"], "DONE")

    def test_unknown_job_raises(self):
        q = LocalJobQueue()
        with self.assertRaises(KeyError):
            q.poll("nope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
