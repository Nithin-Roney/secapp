from django.shortcuts import render, redirect
import requests
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from .models import *
import nmap
import json
import subprocess
import os
import tempfile

from .scanner_modules import *


# Create your views here.



def home(request):
    return render(request, 'home.html')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        print(username,email,password)

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username Exists.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email Exists.')
        else:        
            user = User.objects.create_user(username=username,email=email, password=password)
            user.save()
            login(request, user)
            messages.success(request, 'Login successfully.')
            print("login successfully")
            return redirect(security_scan_view)
    return render(request, 'register.html')


def loginuser(request):
    if request.user.is_authenticated:
        return redirect(loginuser)
    if request.method == 'POST':
       
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(username,password)

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Login successfully.')
            print("login successfully")
            return redirect(multi_scan)
        else:
            messages.error(request, 'Invalid Username or Password.')
    return render(request, 'login.html')

def logoutuser(request):
    logout(request)
    messages.success(request,"Logout Successfully")
    return redirect(home)

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        score = 100
        report = []

        tests = [
            ("Content-Security-Policy", -25, "Content Security Policy (CSP) header not implemented.", "CSP helps mitigate cross-site scripting (XSS) attacks."),
            ("Strict-Transport-Security", -20, "Strict Transport Security (HSTS) header not implemented.", "HSTS enforces secure (HTTPS) connections, protecting against man-in-the-middle (MITM) attacks."),
            ("X-Content-Type-Options", -5, "X-Content-Type-Options header not implemented.", "This header prevents browsers from interpreting files as a different MIME type."),
            ("X-Frame-Options", -20, "X-Frame-Options (XFO) header not implemented.", "This header prevents clickjacking attacks."),
            ("Referrer-Policy", -10, "Referrer-Policy header not implemented.", "This header controls how much referrer information is sent with requests, reducing leakage of sensitive data."),
        ]

        for header, penalty, message, impact in tests:
            if header not in headers:
                score += penalty
                report.append({
                    "header": header,
                    "status": "Failed",
                    "message": message,
                    "impact": impact
                })
            else:
                report.append({
                    "header": header,
                    "status": "Passed",
                    "message": "Header is present.",
                    "impact": "No impact."
                })

        cookies = response.cookies
        secure_cookie_found = False
        for cookie in cookies:
            if not cookie.secure:
                score -= 40
                report.append({
                    "header": "Cookies",
                    "status": "Failed",
                    "message": "Session cookie set without Secure flag.",
                    "impact": "Session cookies sent over non-HTTPS connections are vulnerable to interception."
                })
                break
            else:
                secure_cookie_found = True

        if secure_cookie_found:
            report.append({
                "header": "Cookies",
                "status": "Passed",
                "message": "All cookies are set with Secure flag.",
                "impact": "No impact."
            })

        if score == 100:
            grade = "A+ (Excellent)"
        elif score >= 90:
            grade = "A (Good)"
        elif score >= 75:
            grade = "B (Fair)"
        elif score >= 50:
            grade = "C (Needs Improvement)"
        else:
            grade = "D (Poor)"

        result = {
            "url": url,
            "score": max(0, score),
            "grade": grade,
            "report": report
        }
        return result

    except requests.exceptions.RequestException:
        return {"error": "Could not connect to the website."}


@login_required
def security_scan_view(request):
    if request.method == "POST":
        url = request.POST.get("url")
        if not url:
            return render(request, 'header_scan.html', {
                "results": HeaderScan.objects.filter(user=request.user),
                "error": "Please provide a valid URL."
            })

        result = check_security_headers(url)

        if 'error' not in result:
            header_scan = HeaderScan(
                user=request.user,
                url=url,
                grade=result['grade'],
                score=result['score'],
                report=result['report']
            )
            header_scan.save()

        return render(request, 'header_scan.html', {
            "result": result,
            "results": HeaderScan.objects.filter(user=request.user)
        })

    return render(request, 'header_scan.html', {
        "results": HeaderScan.objects.filter(user=request.user).order_by('-created_on')
    })

@login_required
def port_scan(request):
    if request.method == "POST":
        target = request.POST.get('ip')
        scanner = nmap.PortScanner()

        try:
            scanner.scan(target, '20-1000')
            open_ports = {port: scanner[target]['tcp'][port] for port in scanner[target]['tcp']}

            PortScan.objects.create(
                user=request.user,
                target_ip=target,
                ports=open_ports
            )

            return render(request, 'port_scan.html', {"target": target, "open_ports": open_ports,"results": PortScan.objects.filter(user=request.user).order_by('-created_on')})

        except Exception as e:
            return render(request, 'port_scan.html', {"error": str(e)}, status=400)

    return render(request, 'port_scan.html', {
        "results": PortScan.objects.filter(user=request.user).order_by('-created_on')
    })

@login_required
def technology_detection(request):
    if request.method=="POST":
        url = request.POST.get("url")
        
        

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                temp_file_path = temp_file.name

            result = subprocess.run(
                ['wappalyzer', '-i', url, '-oJ', temp_file_path],
                capture_output=True,
                text=True,
                check=True
            )

            with open(temp_file_path, 'r') as json_file:
                technologies = json.load(json_file)

            os.remove(temp_file_path)

            TechnologyDetection.objects.create(
                user=request.user,
                url=url,
                tech=technologies
            )

            return render(request, 'technology_detection.html', {"url": url, "tech_data": technologies,"results": TechnologyDetection.objects.filter(user=request.user).order_by('-created_on')})

        except subprocess.CalledProcessError as e:
            return render(request, 'technology_detection.html', {
                "error": "Failed to analyze technologies",
                "details": str(e),
                "stderr": e.stderr
            })
        except json.JSONDecodeError:
            return render(request, 'technology_detection.html', {"error": "Failed to parse Wappalyzer output"})
        except Exception as e:
            return render(request, 'technology_detection.html', {"error": "An unexpected error occurred", "details": str(e)})
    return render(request,'technology_detection.html',{"results": TechnologyDetection.objects.filter(user=request.user).order_by('-created_on')})



SQLI_PAYLOADS = [
    "' OR 1=1 --",  
    "' UNION SELECT null,null --", 
    "' AND SLEEP(5) --", 
]


@login_required
def sql_injection_scan(request):
    if request.method=="POST":
        url=request.POST.get("url")
        results = {}
        for payload in SQLI_PAYLOADS:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if "SQL syntax" in response.text or "MySQL" in response.text:
                    results[payload] = "Possible SQL Injection Detected"
                elif response.elapsed.total_seconds() > 4:
                    results[payload] = "Possible Time-Based SQL Injection"
            except requests.exceptions.RequestException:
                results[payload] = "Error in request"

        SQLInjectionScan.objects.create(
            user=request.user,
            url=url,
            results=results
        )

        return render(request,'sql.html',{"url": url, "result": results,"results": SQLInjectionScan.objects.filter(user=request.user).order_by('-created_on')})
    return render(request,'sql.html',{"results": SQLInjectionScan.objects.filter(user=request.user).order_by('-created_on')})  



XSS_PAYLOADS = [
    "<script>confirm('XSS')</script>",  # Standard alert
    "<img src=x onerror=alert('XSS')>",  # Image-based
    "javascript:alert(document.cookie)",  # JavaScript URL
    "<svg/onload=alert('XSS')>",  # SVG-based
    "<a href=javascript:alert('XSS')>Click</a>",  # Anchor href XSS
]


@login_required
def xss_scan(request):
        
    if request.method=="POST":
        url=request.POST.get("url")
        results = {}
        for payload in XSS_PAYLOADS:
            test_url = f"{url}?input={payload}"
            try:
                response = requests.get(test_url)
                if payload in response.text:
                    results[payload] = "Potential XSS Detected"
                else:
                    results[payload] = "No XSS Detected"
            except requests.exceptions.RequestException:
                results[payload] = "Error in request"

        XSSScan.objects.create(
            user=request.user,
            url=url,
            results=results
        )

        return render(request,'xss.html',{"url": url, "result": results,"results": XSSScan.objects.filter(user=request.user).order_by('-created_on')})
    return render(request,'xss.html',{"results": XSSScan.objects.filter(user=request.user).order_by('-created_on')})




REDIRECT_PAYLOADS = [
    "//evil.com",
    "/\\evil.com",
    "/%2Fevil.com",
    "https://google.com/%2Fevil.com",
    "data:text/html,<script>window.location='https://evil.com'</script>",
]


@login_required
def open_redirect_scan(request):
    if request.method=="POST":
        url=request.POST.get("url")
        results = {}
        for payload in REDIRECT_PAYLOADS:
            test_url = f"{url}?r={payload}"
            try:
                response = requests.get(test_url, allow_redirects=False)
                if "location" in response.headers and payload in response.headers["location"]:
                    results[payload] = "Potential Open Redirect Found"
                else:  
                    results[payload] = "No Open Redirect Found"
            except requests.exceptions.RequestException:
                results[payload] = "Error in request"

        OpenRedirectScan.objects.create(
            user=request.user,
            url=url,
            results=results
        )
        return render(request,'open.html',{"url": url, "result": results,"results": OpenRedirectScan.objects.filter(user=request.user).order_by('-created_on')})
    return render(request,'open.html',{"results": OpenRedirectScan.objects.filter(user=request.user).order_by('-created_on')})




SSTI_PAYLOADS = [
    "{{7*7}}",  # Jinja/Flask
    "{% 7*7 %}",  # Django Template Engine
    "${7*7}",  # Velocity Template Language
    "#{7*7}",  # Freemarker
    "<%= 7*7 %>",
]


@login_required
def ssti_scan(request):
    if request.method=="POST":
        url=request.POST.get("url")
        results = {}
        for payload in SSTI_PAYLOADS:
            test_url = f"{url}?input={payload}"
            try:
                response = requests.get(test_url)
                if "49" in response.text:
                    results[payload] = "Potential SSTI Detected"
                else:
                    results[payload] = "No SSTI Detected"
            except requests.exceptions.RequestException:
                results[payload] = "Error in request"



        SSTIScan.objects.create(
            user=request.user,
            url=url,
            results=results
        )
        return render(request,'ssti.html',{"url": url, "result": results,"results": SSTIScan.objects.filter(user=request.user).order_by('-created_on')})
    return render(request,'ssti.html',{"results": SSTIScan.objects.filter(user=request.user).order_by('-created_on')})











SSTI_PAYLOADS = [
    "{{7*7}}",  # Jinja/Flask
    "{% 7*7 %}",  # Django
    "${7*7}",  # Velocity
    "#{7*7}",  # Freemarker
    "<%= 7*7 %>"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=alert(1)\","
]

SQLI_PAYLOADS = [
    "' OR 1=1 -- ",
    "admin' --",
    "' OR 'a'='a"
]

# server side template injection
def check_ssti(url):
    results = {}
    for payload in SSTI_PAYLOADS:
        try:
            res = requests.get(f"{url}?input={payload}")
            results[payload] = "Potential SSTI" if "49" in res.text else "No SSTI"
        except:
            results[payload] = "Error"
    return results


# cross site scripting
def check_xss(url):
    results = {}
    for payload in XSS_PAYLOADS:
        try:
            res = requests.get(f"{url}?input={payload}")
            results[payload] = "Potential XSS" if payload in res.text else "No XSS"
        except:
            results[payload] = "Error"
    return results

def check_sqli(url):
    results = {}
    for payload in SQLI_PAYLOADS:
        try:
            res = requests.get(f"{url}?id={payload}")
            results[payload] = "Potential SQLi" if any(x in res.text.lower() for x in ["mysql", "syntax", "sql error"]) else "No SQLi"
        except:
            results[payload] = "Error"
    return results

def check_lfi(url):
    results = {}
    for path in ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]:
        try:
            res = requests.get(f"{url}?file={path}")
            if "root:x:" in res.text or "[extensions]" in res.text:
                results[path] = "LFI Detected"
            else:
                results[path] = "Not Vulnerable"
        except:
            results[path] = "Error"
    return results

def check_redirect(url):
    payload = "https://example.com"
    try:
        res = requests.get(f"{url}?next={payload}", allow_redirects=False)
        return {payload: "Open Redirect" if payload in res.headers.get("Location", "") else "Safe"}
    except:
        return {payload: "Error"}
    

def check_headers(url):
    results = {}
    try:
        res = requests.get(url)
        missing = []
        for header in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            if header not in res.headers:
                missing.append(header)
        results["Missing Headers"] = missing if missing else "All Secure"
    except:
        results["Missing Headers"] = "Error"
    return results

@login_required
def multi_scan(request):
    if request.method == "POST":
        url = request.POST.get("url")
        scan_types = request.POST.getlist("scan_type")
        results = {}

        if "ssti" in scan_types:
            results["SSTI"] = check_ssti(url)
        if "xss" in scan_types:
            results["XSS"] = check_xss(url)
        if "sqli" in scan_types:
            results["SQLi"] = check_sqli(url)
        if "lfi" in scan_types:
            results["LFI"] = check_lfi(url)
        if "redirect" in scan_types:
            results["Open Redirect"] = check_redirect(url)
        if "headers" in scan_types:
            results["Security Headers"] = check_headers(url)

        VulnerabilityScan.objects.create(user=request.user, url=url, results=results)
        history = VulnerabilityScan.objects.filter(user=request.user).order_by('-created_on')
        return render(request, 'multi_scan.html', {"url": url, "result": results, "results": history})

    history = VulnerabilityScan.objects.filter(user=request.user).order_by('-created_on')
    return render(request, 'multi_scan.html', {"results": history})