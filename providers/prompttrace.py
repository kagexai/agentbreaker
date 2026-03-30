#!/usr/bin/env python3
import sys
import json
import os
import requests

def main():
    # 1. Read the incoming attack payload from AgentBreaker (via stdin)
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({"error": "No input received"}))
            return 0
        data = json.loads(raw_input)
    except Exception as e:
        print(json.dumps({"error": f"Failed to parse stdin: {e}"}))
        return 0

    # 2. Handle healthcheck
    if data.get("healthcheck"):
        print(json.dumps({"ok": True, "text": "PromptTrace provider loaded"}))
        return 0

    payload_text = data.get("text", "")
    
    # 3. Determine which challenge to hit.
    # We default to 'hello-injection', but allow overriding via environment variable.
    challenge = os.environ.get("PROMPTTRACE_CHALLENGE", "").strip()
    if not challenge:
        challenge = "hello-injection"
    
    # 4. Extract authentication cookies from environment
    cookie_str = os.environ.get("PROMPTTRACE_COOKIE", "")
    if not cookie_str:
        print(json.dumps({
            "error": "Missing PROMPTTRACE_COOKIE environment variable. Please export your session cookies."
        }))
        return 0

    # 5. Build the API request
    url = f"https://prompttrace.airedlab.com/api/lab/{challenge}/stream"
    
    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "cookie": cookie_str,
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    }
    
    req_body = {
        "userMessage": payload_text,
        "sessionId": None
    }
    
    # 6. Send the request
    try:
        # Note: The stream endpoint might return SSE (Server-Sent Events) or plain text. 
        # We'll stream it and accumulate the text.
        response = requests.post(url, headers=headers, json=req_body, timeout=30, stream=True)
        response.raise_for_status()
        
        extracted_text = ""
        # Handle SSE format: data: "chunk"
        for line in response.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                if decoded_line.startswith('data: '):
                    # Data is usually JSON-ified string chunks in SSE
                    data_str = decoded_line[6:]
                    if data_str == '[DONE]':
                        break
                    try:
                        # Attempt to parse as JSON string
                        chunk = json.loads(data_str)
                        if isinstance(chunk, str):
                            extracted_text += chunk
                        elif isinstance(chunk, dict):
                            # The stream might return {"message": "..."} chunks or similar
                            if "message" in chunk:
                                extracted_text += str(chunk["message"])
                            elif "text" in chunk:
                                extracted_text += str(chunk["text"])
                            else:
                                extracted_text += json.dumps(chunk)
                    except json.JSONDecodeError:
                        extracted_text += data_str + "\n"
                else:
                    # In case it's not strictly SSE formatted
                    extracted_text += decoded_line + "\n"
        
        # If no SSE format was found but we got content, fallback to raw text
        if not extracted_text.strip() and response.text:
            extracted_text = response.text

    except requests.RequestException as e:
        print(json.dumps({
            "error": f"HTTP Request failed: {e}",
            "text": ""
        }))
        return 0

    # 7. Output the required JSON format for AgentBreaker
    result = {
        "text": extracted_text.strip(),
        # We can attempt basic heuristic to guess if it solved the lab,
        # but the LLM Judge in AgentBreaker will do the real scoring!
        "breach": "congratulations" in extracted_text.lower() or "flag" in extracted_text.lower()
    }
    
    print(json.dumps(result))
    return 0

if __name__ == "__main__":
    sys.exit(main())
