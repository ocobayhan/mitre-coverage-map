import argparse
import json
import tempfile
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as conditions
from selenium.webdriver.support.ui import WebDriverWait


def _open_panel(driver, wait, section, panel_id):
    """Faz 3 sonrasi navigasyon: once bolume, sonra alt sekmeye tikla.

    Paneller artik ust seviye ekran degil; 4 bolumun altinda sekme.
    Bolumde tek gorunur sekme varsa cubuk gizlendigi icin sekmeye tiklamaya
    gerek kalmaz (bolum zaten o paneli acar).
    """
    driver.find_element(By.CSS_SELECTOR, f'.nav-item[data-section="{section}"]').click()
    tabs = driver.find_elements(By.CSS_SELECTOR, f'.section-tab[data-panel="{panel_id}"]')
    if tabs:
        tabs[0].click()
    wait.until(lambda b: "active" in b.find_element(By.ID, panel_id).get_attribute("class"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8888")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="Admin123!")
    parser.add_argument("--output-dir", default=tempfile.gettempdir())
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1440,1000")
    options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    driver = webdriver.Chrome(options=options)
    wait = WebDriverWait(driver, 20)
    result = {"screenshots": {}, "metrics": {}, "console_errors": []}
    try:
        driver.get(f"{args.base_url}/login")
        driver.find_element(By.ID, "username").send_keys(args.username)
        driver.find_element(By.ID, "password").send_keys(args.password)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        wait.until(conditions.url_to_be(f"{args.base_url}/"))
        wait.until(lambda browser: len(browser.find_elements(By.CLASS_NAME, "tactic-column")) >= 10)
        result["metrics"]["tactic_columns"] = len(
            driver.find_elements(By.CLASS_NAME, "tactic-column")
        )
        matrix_path = output_dir / "mitre-matrix-desktop.png"
        driver.save_screenshot(str(matrix_path))
        result["screenshots"]["matrix_desktop"] = str(matrix_path)

        # Ortam secici (Faz 2) — matris uzerinde varlik grubu filtresi
        result["metrics"]["scope_select_options"] = len(
            driver.find_elements(By.CSS_SELECTOR, "#matrixScopeSelect option")
        )

        # Teknik detay modali: Mitigations + Tespitler + Aksiyonlar
        driver.find_element(By.CSS_SELECTOR, "#matrix .technique-card .detail-btn").click()
        wait.until(conditions.visibility_of_element_located((By.ID, "modalBody")))
        result["metrics"]["modal_tabs"] = len(driver.find_elements(By.CSS_SELECTOR, "#ruleModal .tab-btn"))
        # Duplike mitigation ozeti kaldirildi — 0 olmali
        result["metrics"]["modal_duplicate_mitigation_summary"] = len(
            driver.find_elements(By.CSS_SELECTOR, "#ruleModal .mitigation-summary-section")
        )
        driver.find_element(By.ID, "modalClose").click()

        # Faz 3: 4 bolum + alt sekmeler
        result["metrics"]["nav_sections"] = len(
            driver.find_elements(By.CSS_SELECTOR, '.nav-item[data-section]')
        )
        _open_panel(driver, wait, "inventory", "scopePanel")
        wait.until(lambda browser: len(browser.find_elements(By.CSS_SELECTOR, "#scopeSummary .ops-stat")) == 4)
        scope_path = output_dir / "mitre-scope-registry-desktop.png"
        driver.save_screenshot(str(scope_path))
        result["screenshots"]["scope_registry_desktop"] = str(scope_path)
        result["metrics"]["scope_summary_stats"] = len(driver.find_elements(By.CSS_SELECTOR, "#scopeSummary .ops-stat"))
        result["metrics"]["scope_monitoring_rows"] = len(driver.find_elements(By.CSS_SELECTOR, ".scope-monitor-row"))
        driver.set_window_size(390, 844)
        scope_mobile_path = output_dir / "mitre-scope-registry-mobile.png"
        driver.save_screenshot(str(scope_mobile_path))
        result["screenshots"]["scope_registry_mobile"] = str(scope_mobile_path)
        result["metrics"]["scope_mobile_document_width"] = driver.execute_script("return document.documentElement.scrollWidth")
        result["metrics"]["scope_mobile_viewport_width"] = driver.execute_script("return document.documentElement.clientWidth")
        driver.set_window_size(1440, 1000)

        _open_panel(driver, wait, "gaps", "dataQualityPanel")
        wait.until(lambda browser: browser.find_element(By.ID, "qualitySummary").text.strip())
        quality_path = output_dir / "mitre-data-quality-desktop.png"
        driver.save_screenshot(str(quality_path))
        result["screenshots"]["data_quality_desktop"] = str(quality_path)
        result["metrics"]["quality_stats"] = len(
            driver.find_elements(By.CSS_SELECTOR, "#qualitySummary .ops-stat")
        )
        result["metrics"]["quality_issue_rows"] = len(
            driver.find_elements(By.CSS_SELECTOR, "#qualityIssuesBody tr")
        )

        _open_panel(driver, wait, "settings", "auditPanel")
        wait.until(lambda browser: browser.find_element(By.ID, "auditIntegrity").text != "Kontrol ediliyor")
        audit_path = output_dir / "mitre-audit-desktop.png"
        driver.save_screenshot(str(audit_path))
        result["screenshots"]["audit_desktop"] = str(audit_path)
        result["metrics"]["audit_rows"] = len(
            driver.find_elements(By.CSS_SELECTOR, "#auditTableBody tr")
        )

        driver.set_window_size(390, 844)
        mobile_path = output_dir / "mitre-audit-mobile.png"
        driver.save_screenshot(str(mobile_path))
        result["screenshots"]["audit_mobile"] = str(mobile_path)
        result["metrics"]["mobile_scroll_width"] = driver.execute_script(
            "return document.documentElement.scrollWidth"
        )
        result["metrics"]["mobile_viewport_width"] = driver.execute_script(
            "return document.documentElement.clientWidth"
        )
        result["metrics"]["mobile_sidebar_width"] = driver.execute_script(
            "return Math.round(document.querySelector('.sidebar').getBoundingClientRect().width)"
        )
        result["metrics"]["mobile_audit_actions"] = driver.execute_script(
            "const e=document.querySelector('#auditPanel .ops-actions');"
            "const r=e.getBoundingClientRect();"
            "return {display:getComputedStyle(e).display,x:Math.round(r.x),y:Math.round(r.y),width:Math.round(r.width),height:Math.round(r.height)}"
        )
        result["metrics"]["mobile_audit_header"] = driver.execute_script(
            "const e=document.querySelector('#auditPanel .ops-header');"
            "const r=e.getBoundingClientRect();return {height:Math.round(r.height),y:Math.round(r.y),overflow:getComputedStyle(e).overflow}"
        )

        result["console_errors"] = [
            entry for entry in driver.get_log("browser") if entry["level"] == "SEVERE"
        ]
    finally:
        driver.quit()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["console_errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
