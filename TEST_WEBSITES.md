# Safe Websites for Security Testing

## ✅ Recommended Test Websites

### 1. **Test/Demo Websites (Designed for Testing)**
- `https://example.com` - Simple test site, always available
- `https://httpbin.org` - HTTP testing service, allows testing
- `https://httpstat.us` - HTTP status code testing
- `https://jsonplaceholder.typicode.com` - API testing site
- `https://reqres.in` - API testing platform

### 2. **Security Testing Platforms**
- `https://portswigger.net/web-security` - PortSwigger Web Security Academy (educational)
- `https://owasp.org` - OWASP website (allows security testing)
- `https://hackthebox.com` - HTB website (if you have account)

### 3. **Public Websites (Generally Safe to Scan)**
- `https://github.com` - GitHub (public repos, allows scanning)
- `https://stackoverflow.com` - Stack Overflow
- `https://wikipedia.org` - Wikipedia
- `https://reddit.com` - Reddit (public content)

### 4. **Your Own Websites**
- Your personal website/blog
- Development/staging environments you own
- Local test servers (localhost)

### 5. **Educational/Testing Services**
- `https://testphp.vulnweb.com` - Acunetix test site (designed for testing)
- `https://demo.testfire.net` - IBM test site (designed for testing)
- `https://zero.webappsecurity.com` - Test banking site (designed for testing)

## ⚠️ Important Notes

1. **Always get permission** before scanning any website
2. **Use test sites** designed for security testing when possible
3. **Respect robots.txt** and rate limits
4. **Don't scan** production systems without explicit permission
5. **Be ethical** - only scan what you're authorized to test

## 🎯 Best Practices

- Start with `example.com` or `httpbin.org` for basic testing
- Use dedicated test sites for vulnerability testing
- Scan your own websites first
- Check website's security.txt or terms of service before scanning

## 📝 Example Scan Commands

```bash
# General scan
curl -X POST http://localhost:4444/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "async": true}'

# Payment scan
curl -X POST http://localhost:4444/api/scan/payment \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com/checkout", "async": true}'
```

