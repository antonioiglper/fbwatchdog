import streamlit as st
import re
from contextlib import nullcontext
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import whois
from datetime import datetime, timezone

# Page configuration
st.set_page_config(
    page_title="FB Watchdog - E-Commerce Fraud Detector",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 FB Watchdog - E-Commerce Fraud Detector")
st.write("Analyze e-commerce domains for fraud indicators, suspicious patterns, and compliance issues.")

# US States list
us_states = [
    "alabama", "alaska", "arizona", "arkansas", "california", "colorado",
    "connecticut", "delaware", "florida", "georgia", "hawaii", "idaho",
    "illinois", "indiana", "iowa", "kansas", "kentucky", "louisiana",
    "maine", "maryland", "massachusetts", "michigan", "minnesota", "mississippi",
    "missouri", "montana", "nebraska", "nevada", "new hampshire", "new jersey",
    "new mexico", "new york", "north carolina", "north dakota", "ohio",
    "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina",
    "south dakota", "tennessee", "texas", "utah", "vermont", "virginia",
    "washington", "west virginia", "wisconsin", "wyoming"
]

# ========================================
# ANALYSIS FUNCTIONS
# ========================================

def extract_shopify_policies_fallback(base_url, soup):
    policy_keywords = [
        "refund", "return", "returns", "reembolso", "devolución",
        "terms", "terminos", "devoluciones", "service", "servicio"
    ]
    links = soup.find_all("a", href=True)
    policy_links = []
    for a in links:
        href = a["href"].lower()
        text_link = a.get_text(strip=True).lower()
        if any(k in href for k in policy_keywords) or any(k in text_link for k in policy_keywords):
            full_url = urljoin(base_url, href)
            policy_links.append(full_url)
    return list(set(policy_links))

def detect_return_red_flags(policy_links):
    red_flags = [
        "return to asia", "return to china", "return to hong kong",
        "return to singapore", "return to warehouse in",
        "customer pays return shipping", "return shipping is not free",
        "return shipping fee", "international return", "restocking fee",
        "non-refundable", "buyer is responsible for return shipping",
        "los gastos de devolución corren por cuenta del cliente",
        "devolución no gratuita", "envío de devolución no incluido", "en asia", "in asia"
    ]
    found_flags = []
    for link in policy_links:
        try:
            r = requests.get(link, timeout=10)
            r.raise_for_status()
            psoup = BeautifulSoup(r.text, "html.parser")
            ptext = psoup.get_text(separator=" ").lower()
            for flag in red_flags:
                if flag in ptext:
                    found_flags.append((flag, link))
        except:
            continue
    return found_flags

def detect_non_uk_countries(policy_links, us_states):
    countries = [
        "china", "hong kong", "singapore", "india", "pakistan", "bangladesh",
        "usa", "united states", "canada", "australia", "new zealand",
        "france", "germany", "spain", "italy", "portugal", "netherlands",
        "poland", "czech", "romania", "bulgaria", "slovakia", "slovenia",
        "sweden", "norway", "finland", "denmark",
        "mexico", "brazil", "argentina", "chile",
        "turkey", "russia", "ukraine", "japan", "south korea",
        "vietnam", "thailand", "malaysia", "philippines", "llc"
    ] + us_states
    found = []
    for link in policy_links:
        if "terms" not in link.lower() and "terminos" not in link.lower():
            continue
        try:
            r = requests.get(link, timeout=10)
            r.raise_for_status()
            psoup = BeautifulSoup(r.text, "html.parser")
            ptext = psoup.get_text(separator=" ").lower()
            for country in countries:
                if country in ptext:
                    found.append((country, link))
        except:
            continue
    return found

def detect_fake_uk_addresses(text):
    text = text.lower()
    fake_patterns = [
        "london ec1v", "27 old gloucester", "71-75 shelton street",
        "kemp house", "virtual office", "mailbox", "po box", "unit", "suite", "warehouse"
    ]
    uk_postcode_regex = r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b"
    found = []
    for pattern in fake_patterns:
        if pattern in text:
            found.append(pattern)
    if ("united kingdom" in text or "uk" in text) and not re.search(uk_postcode_regex, text, re.IGNORECASE):
        found.append("missing_valid_uk_postcode")
    return found

def detect_missing_company_number(text):
    text = text.lower()
    required_terms = [
        "company number", "registered in england", "registered in scotland",
        "companies house", "crn"
    ]
    if "united kingdom" in text or "uk" in text or "england" in text:
        if not any(term in text for term in required_terms):
            return True
    return False

def detect_vat_fraud(text):
    text = text.lower()
    vat_regex = r"\b(gb)?\d{9}\b"
    if "vat" in text:
        if not re.search(vat_regex, text):
            return "vat_claimed_but_no_valid_number"
        if "000000000" in text:
            return "fake_vat_number"
    return None

def detect_us_llc_patterns(text, us_states):
    text = text.lower()
    found = []
    if "llc" in text:
        for state in us_states:
            if state in text:
                found.append(state)
    return found

def domain_age_report(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - created).days
        age_months = age_days / 30.44
        age_years = age_days / 365.25
        
        if age_months < 1:
            risk = "⚠️ Extremely new domain — very high risk"
        elif age_months < 3:
            risk = "⚠️ New domain — suspicious for Shopify stores"
        elif age_months < 12:
            risk = "🟡 Moderately new — check other signals"
        else:
            risk = "🟢 Established domain — low age‑related risk"
        
        return {
            "created": created,
            "age_days": age_days,
            "age_months": round(age_months, 1),
            "age_years": round(age_years, 2),
            "risk": risk,
        }
    except Exception as e:
        return {"error": str(e)}

def scan_trustpilot(domain):
    api_url = f"https://www.trustpilot.com/api/business-units/find?domain={domain}"
    try:
        r = requests.get(api_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return {"exists": False, "reason": "No Trustpilot profile found"}
        data = r.json()
        if not data or "id" not in data:
            return {"exists": False, "reason": "No Trustpilot profile found"}
        return {
            "exists": True,
            "name": data.get("displayName"),
            "trustscore": data.get("trustScore"),
            "reviews": data.get("numberOfReviews"),
            "url": f"https://www.trustpilot.com/review/{domain}"
        }
    except Exception as e:
        return {"exists": False, "reason": str(e)}

# ========================================
# UI: Input Section
# ========================================

col1, col2 = st.columns([3, 1], vertical_alignment="bottom")
with col1:
    domain_input = st.text_input(
        "Enter domain to analyze:",
        placeholder="example.com",
        help="Enter a domain without http:// or www."
    )
with col2:
    analyze_button = st.button("🔍 Analyze", use_container_width=True)

if analyze_button and domain_input:
    domain = domain_input.strip().lower().replace("www.", "")
    
    # Ensure https:// prefix
    if not domain.startswith("http"):
        url = f"https://{domain}"
    else:
        url = domain
        domain = urlparse(url).netloc.replace("www.", "")
    
    with st.spinner("Analyzing domain..."):
        try:
            # Fetch page
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.get_text()
            html = response.text.lower()
            
            # ========================================
            # RESULTS DISPLAY
            # ========================================
            
            st.divider()
            st.subheader(f"Analysis Results for: {domain}")
            st.divider()
            
            # --- DOMAIN AGE ---
            with st.expander("📅 Domain Age Analysis", expanded=True):
                age_data = domain_age_report(domain)
                if "error" not in age_data:
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Created", age_data["created"].strftime("%Y-%m-%d"))
                    col2.metric("Age", f"{age_data['age_months']} months")
                    col3.metric("Risk Level", age_data["risk"])
                else:
                    st.warning(f"Could not fetch domain info: {age_data['error']}")
            
            # --- EMAIL & PHONE ---
            with st.expander("📧 Contact Information"):
                phone_pattern = re.compile(
                    r"(\+\d{1,3}\s?)?((\(\d{3}\)\s?)|(\d{3}[-.\s]?))?\d{3}[-.\s]?\d{4}"
                )
                phones = [m.group(0) for m in phone_pattern.finditer(text)]
                email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                emails = [m.group(0) for m in email_pattern.finditer(text)]
                
                if emails:
                    st.write("**Emails found:**")
                    for email in emails[:10]:  # Limit display
                        st.write(f"- {email}")
                else:
                    st.info("No emails found")
                
                if phones:
                    st.write("**Phone numbers found:**")
                    for phone in phones[:10]:
                        st.write(f"- {phone}")
                else:
                    st.info("No phone numbers found")
            
            # --- SHOPIFY DETECTION ---
            with st.expander("🛍️ Platform Detection"):
                shopify_signals = [
                    "cdn.shopify.com", "shopifyassets", "x-shopify",
                    "shopify-checkout-api", "shopify.theme", "shopify"
                ]
                is_shopify = any(sig in html for sig in shopify_signals)
                
                if not is_shopify:
                    try:
                        cart_test = requests.get(url.rstrip("/") + "/cart.js", timeout=5)
                        if cart_test.status_code == 200 and "items" in cart_test.text:
                            is_shopify = True
                    except:
                        pass
                
                if is_shopify:
                    st.success("✅ Shopify store detected")
                else:
                    st.info("ℹ️ Not a Shopify store (or not detectable)")
            
            # --- POLICY EXTRACTION ---
            with st.expander("📋 Terms & Policies"):
                policy_links = []
                if is_shopify:
                    policies_url = url.rstrip("/") + "/policies.json"
                    try:
                        policies_response = requests.get(policies_url, timeout=10)
                        policies_response.raise_for_status()
                        policies_data = policies_response.json()
                        all_policies = policies_data.get("policies", [])
                        if all_policies:
                            for policy in all_policies:
                                policy_links.append(policy["url"])
                    except Exception:
                        policy_links = extract_shopify_policies_fallback(url, soup)
                
                if policy_links:
                    st.write(f"**Found {len(policy_links)} policy links:**")
                    for link in policy_links:
                        st.write(f"- [{link}]({link})")
                else:
                    st.warning("No policy links found")
            
            # --- RED FLAGS ---
            with st.expander("⚠️ Return Policy Red Flags"):
                if policy_links:
                    red_flags = detect_return_red_flags(policy_links)
                    if red_flags:
                        for flag, link in red_flags:
                            st.warning(f"Found: *'{flag}'* in [{link}]({link})")
                    else:
                        st.success("✅ No risky return policy phrases detected")
                else:
                    st.info("No policies to analyze")
            
            # --- TRUSTPILOT ---
            with st.expander("⭐ Trustpilot Profile"):
                tp = scan_trustpilot(domain)
                if tp["exists"]:
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Trust Score", tp.get("trustscore", "N/A"))
                    col2.metric("Reviews", tp.get("reviews", "N/A"))
                    col3.link_button("View on Trustpilot", tp["url"])
                    if tp.get("trustscore") and tp["trustscore"] < 3:
                        st.error("⚠️ Low TrustScore detected — possible scam indicator")
                else:
                    st.warning(f"❌ {tp['reason']}")
            
            # --- FRAUD CHECKS ---
            with st.expander("🚨 Advanced Fraud Indicators"):
                tos_links = [link for link in policy_links if "terms" in link.lower() or "terminos" in link.lower()]
                tos_text = ""
                
                if tos_links:
                    try:
                        r = requests.get(tos_links[0], timeout=10)
                        r.raise_for_status()
                        tos_text = BeautifulSoup(r.text, "html.parser").get_text(separator=" ").lower()
                    except:
                        pass
                
                if tos_text:
                    fraud_found = False
                    
                    fake_uk = detect_fake_uk_addresses(tos_text)
                    if fake_uk:
                        fraud_found = True
                        st.error("⚠️ Fake UK address indicators found:")
                        for item in fake_uk:
                            st.write(f"- {item}")
                    
                    if detect_missing_company_number(tos_text):
                        fraud_found = True
                        st.error("⚠️ Company claims UK presence but no registration number found")
                    
                    vat_issue = detect_vat_fraud(tos_text)
                    if vat_issue:
                        fraud_found = True
                        st.error(f"⚠️ VAT issue detected: {vat_issue}")
                    
                    us_llc = detect_us_llc_patterns(tos_text, us_states)
                    if us_llc:
                        fraud_found = True
                        st.error(f"⚠️ U.S. LLC jurisdiction detected: {', '.join(us_llc)}")
                    
                    if not fraud_found:
                        st.success("✅ No major fraud indicators detected")
                else:
                    st.info("No Terms of Service found for analysis")
        
        except requests.exceptions.RequestException as e:
            st.error(f"❌ Failed to fetch domain: {str(e)}")
        except Exception as e:
            st.error(f"❌ Error during analysis: {str(e)}")

st.divider()
st.markdown("---")
st.markdown("💡 **How to use:** Enter an e-commerce domain to analyze it for fraud indicators, compliance issues, and red flags.")
