from pathlib import Path

from playwright.sync_api import sync_playwright


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "folderbase-readme-banner.html"
OUTPUT = HERE.parent / "folderbase-readme-banner.png"


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(
        viewport={"width": 1600, "height": 640},
        device_scale_factor=1,
    )
    page.goto(SOURCE.as_uri(), wait_until="load")
    page.evaluate("document.fonts.ready")
    dimensions = page.evaluate(
        "({ width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight })"
    )
    assert dimensions == {"width": 1600, "height": 640}, dimensions
    page.screenshot(path=str(OUTPUT), full_page=False, animations="disabled")
    browser.close()
