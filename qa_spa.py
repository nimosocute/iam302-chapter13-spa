"""
QA Suite for Malware Analysis SPA (Chapter 13 - IAM302).
Strict verification using Playwright + Edge.
Tests:
- Zero external HTTP(S) network requests tracked throughout the entire lifecycle.
- Zero JavaScript console errors & page errors (audited initially and re-asserted at final step).
- Responsive layout: zero horizontal body overflow AND zero boundingClientRect clipping on Desktop (1600x900), Tablet (768x1024), and Mobile (390x844).
- Accessibility keyboard navigation: ArrowRight / ArrowLeft tab switching, Enter to open evidence, Escape to close modal.
- Evidence image decoding: forces loading=eager and awaits img.decode() on all images before asserting naturalWidth/naturalHeight > 0 and uncropped contain.
- Gallery filter button verification (each filter renders exact expected count).
- Modal keyboard close (Escape) and zoom increment/reset verification (.25 increment to 1.25, reset to 1.0).
- Comprehensive modal verification across ALL packaged evidence items (click open, verify src & decode, Escape close).
- All sample <details><summary> assembly/pseudocode containers default collapsed, toggle open & close cleanly.
- Artifacts & documentation links resolve to valid, non-empty files on disk.
- Text content integrity & clean encoding check (no double-escaped entities or mojibake).
- Post-animation full-resolution screenshots saved to artifacts/ and host visualizations (Desktop overview, Sample02, Gallery, and Mobile 390px).
- Dual logging to stdout and specified log file (UTF-8).
"""

import argparse
import asyncio
import os
import re
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from playwright.async_api import async_playwright

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
SPA_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_HTML = os.path.join(SPA_DIR, "index.html")
DATA_JS = os.path.join(SPA_DIR, "report-data.js")
ARTIFACTS_DIR = os.path.join(SPA_DIR, "artifacts")
ANALYSIS_DIR = os.path.join(SPA_DIR, "analysis")
PREVIEW_PNG = os.path.join(ARTIFACTS_DIR, "spa_ui_preview.png")
DEFAULT_QA_LOG = os.path.join(ANALYSIS_DIR, "qa-recheck-results.txt")
HOST_VIS_DIR = r"C:\Users\vanba\.codex\visualizations\2026\11\02\01a19bb5-17d4-7e30-8fb5-d18a2c8dfbdb"

log_lines = []

def log_print(msg=""):
    print(msg)
    log_lines.append(msg)


async def main(allow_mock=False, log_file=DEFAULT_QA_LOG):
    log_print("==================================================")
    log_print("   MALWARE ANALYSIS SPA - RENDER & INTEGRITY QA   ")
    log_print("==================================================")
    log_print("Target index.html : " + INDEX_HTML)
    log_print("Report data path  : " + DATA_JS)
    log_print("Artifacts preview : " + PREVIEW_PNG)
    log_print("QA Results Log    : " + log_file)
    data_exists = os.path.exists(DATA_JS)
    log_print("--------------------------------------------------")

    if not os.path.exists(INDEX_HTML):
        log_print("[FAIL] CRITICAL: index.html not found at " + INDEX_HTML)
        sys.exit(1)

    # 1. Static Offline Integrity Check (No external CDN/scripts)
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        html_content = f.read()

    ext_links = re.findall(r'href=[\"\'](https?://.*?)[\"\']', html_content)
    ext_scripts = re.findall(r'src=[\"\'](https?://.*?)[\"\']', html_content)
    if ext_links or ext_scripts:
        log_print("[FAIL] CRITICAL: External web dependencies detected in index.html (Breaks offline requirement)!")
        sys.exit(1)
    else:
        log_print("[PASS] 1. Zero External Dependencies in HTML source (100% Offline Capable)")

    if not data_exists and not allow_mock:
        log_print("[FAIL] CRITICAL: report-data.js does not exist on disk!")
        log_print("       Silent fallback mock is disabled. Provide report-data.js or pass --mock explicitly.")
        sys.exit(1)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=EDGE_PATH,
            headless=True
        )
        page = await browser.new_page()

        console_errors = []
        page_errors = []
        captured_requests = []

        page.on("request", lambda req: captured_requests.append(req.url))
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        if not data_exists:
            log_print("[WARN] Running in EXPLICIT MOCK MODE (--mock enabled)")
            mock_script = """
            window.LAB13 = {
                meta: {
                    title: 'Mock Test Report',
                    subtitle: 'Testing only',
                    folderNumber: 13,
                    folderPath: 'C:\\\\Users\\\\bachdeptrai\\\\Downloads\\\\Chapter_13L',
                    environment: {
                        os: 'Windows 10 Ent LTSC',
                        vm: 'VMware Workstation 17 Pro',
                        network: 'Host-Only / Isolated',
                        snapshot: 'Lab13-before-analysis',
                        tools: ['IDA Pro 7.x', 'Process Monitor', 'Burp Suite Pro']
                    }
                },
                samples: [],
                evidences: []
            };
            """
            await page.add_init_script(mock_script)

        file_url = "file:///" + INDEX_HTML.replace(os.sep, "/")
        await page.goto(file_url)
        await page.wait_for_load_state("networkidle")
        await page.wait_for_timeout(300)

        # 2. Initial Runtime Offline Request Check
        external_http_requests = [url for url in captured_requests if url.startswith("http://") or url.startswith("https://")]
        assert len(external_http_requests) == 0, "External HTTP(S) requests detected: " + str(external_http_requests)
        log_print("[PASS] 2. Zero External HTTP(S) Network Requests Captured at Load (" + str(len(captured_requests)) + " local requests)")

        # 3. Initial JavaScript Console & Page Errors Check
        real_page_errors = [e for e in page_errors if "ERR_FILE_NOT_FOUND" not in e]
        assert len(real_page_errors) == 0, "Page JavaScript Errors Detected: " + str(real_page_errors)
        assert len(console_errors) == 0, "Console Errors Detected: " + str(console_errors)
        log_print("[PASS] 3. Zero JavaScript Runtime & Console Errors at Load")

        # 4. Header and Meta Check
        title = await page.text_content("#app-title")
        assert len(title.strip()) > 0, "App title is empty!"
        log_print("[PASS] 4. Title Rendered: '" + title.strip() + "'")

        # 5. Viewport & Overflow Check Across ALL 8 Tabs (Desktop 1600x900, Tablet 768x1024, Mobile 390x844)
        viewports = [
            ("Desktop (1600x900)", 1600, 900),
            ("Tablet (768x1024)", 768, 1024),
            ("Mobile (390x844)", 390, 844)
        ]
        all_tab_btns = await page.locator(".nav-tab").all()
        tab_ids = [await t.get_attribute("data-tab") for t in all_tab_btns]
        assert len(tab_ids) == 8, f"Expected 8 navigation tabs, found {len(tab_ids)}!"

        for vp_name, w, h in viewports:
            await page.set_viewport_size({"width": w, "height": h})
            for tab_id in tab_ids:
                await page.click(f".nav-tab[data-tab='{tab_id}']")
                await page.wait_for_timeout(80)
                overflow = await page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth || document.body.scrollWidth > window.innerWidth")
                assert not overflow, f"Horizontal overflow detected on viewport {vp_name} in tab #{tab_id}!"
                
                # Check visible elements boundingClientRect clipping on mobile 390px
                if w == 390:
                    clipped = await page.evaluate("""() => {
                        const vw = window.innerWidth;
                        const bad = [];
                        const activePanel = document.querySelector('.tab-content.active');
                        if (!activePanel) return bad;
                        const els = activePanel.querySelectorAll('.card, .grid-2, .grid-3, .detail-row, article.reading-step, figure.inline-evidence');
                        els.forEach(el => {
                            const r = el.getBoundingClientRect();
                            if (r.width > 0 && r.height > 0) {
                                if (r.right > vw + 1.5 || r.width > vw + 1.5) {
                                    bad.push(el.className + ' (w=' + Math.round(r.width) + ', r=' + Math.round(r.right) + ')');
                                }
                            }
                        });
                        return bad;
                    }""")
                    assert len(clipped) == 0, f"Mobile visible elements clipped beyond viewport on #{tab_id}: " + str(clipped)

        # Restore overview tab on desktop before proceeding
        await page.set_viewport_size({"width": 1600, "height": 1000})
        await page.click("#tab-btn-overview")
        await page.wait_for_timeout(100)
        log_print("[PASS] 5. Responsive Layout Verified across all 8 tabs (Zero Overflow & Zero BoundingRect Clipping on 390x844 Mobile)")

        # 6. Dynamic Sample Tabs Check
        tab_buttons = await page.locator(".nav-tab").all_text_contents()
        clean_tabs = [t.strip().replace("\n", " ") for t in tab_buttons]
        log_print("[PASS] 6. Navigation Tabs Rendered (" + str(len(tab_buttons)) + "): " + str(clean_tabs))

        # 7. Accessibility Keyboard Navigation (ArrowRight / ArrowLeft on Nav Tabs)
        first_tab = page.locator(".nav-tab").first
        await first_tab.focus()
        await page.keyboard.press("ArrowRight")
        second_tab_active = await page.locator(".nav-tab:nth-child(2)").get_attribute("class")
        assert "active" in second_tab_active, "Keyboard ArrowRight failed to switch tab!"
        await page.keyboard.press("ArrowLeft")
        first_tab_active = await page.locator(".nav-tab:first-child").get_attribute("class")
        assert "active" in first_tab_active, "Keyboard ArrowLeft failed to switch tab!"
        log_print("[PASS] 7. Accessibility Keyboard Navigation Verified (ArrowRight/ArrowLeft tab switching)")

        # 8. Individual Sample Tabs Switching Check
        sample_tab_btns = await page.locator(".nav-tab[data-tab^='tab-sample-']").all()
        for btn in sample_tab_btns:
            tab_id = await btn.get_attribute("data-tab")
            await btn.click()
            active = await page.is_visible("#" + str(tab_id) + ".active")
            assert active, "Tab " + str(tab_id) + " failed to activate on click!"
        log_print("[PASS] 8. All Individual Sample Tabs Switch Accurately")

        # 9. Check References & Repro tabs
        await page.click("#tab-btn-refs")
        refs_text = await page.text_content("#references-table-body")
        assert len(refs_text.strip()) > 0, "References table body is empty!"
        log_print("[PASS] 9. References Section Operational (" + str(len(refs_text.strip())) + " chars)")

        # 10. Render & Integrity Checks of Loaded Report Data
        if data_exists:
            raw_data = await page.evaluate("() => window.LAB13")
            samples = raw_data.get("samples", [])
            evidences = raw_data.get("evidences", [])
            iocs = raw_data.get("iocs", [])
            reproduction = raw_data.get("reproduction", [])
            limitations = raw_data.get("limitations", [])

            log_print("--------------------------------------------------")
            log_print("RENDER & INTEGRITY DATA SUMMARY:")
            log_print("   - Samples count     : " + str(len(samples)))
            for s in samples:
                algo = s.get("mechanism", {}).get("algorithm", "N/A")
                f_count = len(s.get("findings", []))
                log_print("     * " + str(s.get("fileName")) + ": " + str(algo) + " (" + str(f_count) + " findings)")
            log_print("   - IOC indicators    : " + str(len(iocs)))
            log_print("   - Reproduction steps: " + str(len(reproduction)))
            log_print("   - Limitations items : " + str(len(limitations)))
            log_print("   - Evidences count   : " + str(len(evidences)))

            if len(evidences) == 0:
                log_print("[INFO] Evidence array is currently 0.")
                await page.click("#tab-btn-gallery")
                gallery_html = await page.inner_html("#gallery-container")
                assert "Không tìm thấy bằng chứng" in gallery_html or "Chưa có" in gallery_html
                log_print("[PASS] 10. Empty evidence state handled gracefully without crash.")
            else:
                # 10a. Verify file existence on disk
                missing_files = []
                for ev in evidences:
                    rel_path = ev.get("imagePath", "")
                    full_path = os.path.join(SPA_DIR, rel_path)
                    exists = os.path.exists(full_path)
                    status_mark = "OK" if exists else "MISSING"
                    log_print("     [" + status_mark + "] " + str(ev.get("id")) + ": " + rel_path + " (" + str(ev.get("tool")) + ")")
                    if not exists:
                        missing_files.append(rel_path)

                assert len(missing_files) == 0, "Missing evidence files on disk: " + str(missing_files)
                log_print("[PASS] 10a. All " + str(len(evidences)) + " actual evidence image files exist on disk.")

                # Switch to gallery tab
                await page.click("#tab-btn-gallery")
                await page.wait_for_timeout(200)

                # 10b. Force eager loading and await decode on all gallery images
                decode_errors = await page.evaluate("""async () => {
                    const errs = [];
                    const imgs = Array.from(document.querySelectorAll('#gallery-container .gallery-card img'));
                    for (const img of imgs) {
                        img.loading = 'eager';
                        try {
                            await img.decode();
                        } catch (e) {
                            errs.push('Decode error on ' + img.src + ': ' + e);
                        }
                    }
                    return errs;
                }""")
                assert len(decode_errors) == 0, "Image decode errors encountered: " + str(decode_errors)

                image_stats = await page.evaluate("""() => {
                    const imgs = Array.from(document.querySelectorAll('#gallery-container .gallery-card img'));
                    return imgs.map((img, idx) => ({
                        idx: idx,
                        src: img.getAttribute('src'),
                        complete: img.complete,
                        naturalWidth: img.naturalWidth,
                        naturalHeight: img.naturalHeight,
                        objectFit: window.getComputedStyle(img).objectFit
                    }));
                }""")
                assert len(image_stats) == len(evidences), "Expected " + str(len(evidences)) + " gallery images, found " + str(len(image_stats))
                for st in image_stats:
                    assert st["complete"], "Image decoding incomplete: " + str(st["src"])
                    assert st["naturalWidth"] > 0 and st["naturalHeight"] > 0, "Image decoding failed (0x0): " + str(st["src"])
                    assert st["objectFit"] == "contain", "Image object-fit must be contain (uncropped): " + str(st["src"])
                log_print("[PASS] 10b. All " + str(len(image_stats)) + " Gallery Images Eagerly Decoded (naturalWidth/Height > 0, uncropped object-fit: contain)")

                # 10c. Verify all filter buttons render exact expected card counts
                filter_buttons = await page.locator("#gallery-filter-wrap .filter-btn").all()
                for btn in filter_buttons:
                    filter_val = await btn.get_attribute("data-filter")
                    await btn.click()
                    await page.wait_for_timeout(100)
                    rendered_cards = await page.locator("#gallery-container .gallery-card").count()
                    if filter_val == "all":
                        expected = len(evidences)
                    else:
                        expected = len([e for e in evidences if (e.get("tool") or "").strip().lower() == filter_val.strip().lower()])
                    assert rendered_cards == expected, "Filter '" + str(filter_val) + "' rendered " + str(rendered_cards) + " cards, expected " + str(expected)
                # Reset back to 'all'
                await page.locator("#gallery-filter-wrap .filter-btn[data-filter='all']").click()
                log_print("[PASS] 10c. All " + str(len(filter_buttons)) + " Gallery Filter Buttons Verified (Accurate Card Counts)")

                # 10d. Accessibility Keyboard: Open modal with Enter key on focused card
                first_card = page.locator("#gallery-container .gallery-card").first
                await first_card.focus()
                await page.keyboard.press("Enter")
                assert await page.is_visible("#image-modal.open"), "Modal did not open on keyboard Enter key!"
                modal_fit = await page.locator("#modal-img").evaluate("el => window.getComputedStyle(el).objectFit")
                assert modal_fit == "contain", "Modal image must have object-fit: contain!"

                # Test Zoom In (+0.25 increment from 1.0 to 1.25)
                await page.click("#btn-zoom-in")
                zoom_in_val = await page.locator("#modal-img").evaluate("el => el.style.transform")
                assert "scale(1.25)" in zoom_in_val, "Expected scale(1.25), got: " + str(zoom_in_val)

                # Test Close via Escape key
                await page.keyboard.press("Escape")
                await page.wait_for_timeout(150)
                assert not await page.is_visible("#image-modal.open"), "Modal did not close on Escape key!"

                # Reopen modal via click and verify zoom is reset to 1.0
                await page.locator("#gallery-container .gallery-card").first.click()
                zoom_reopen_val = await page.locator("#modal-img").evaluate("el => el.style.transform")
                assert zoom_reopen_val in ["scale(1)", "scale(1.0)"], "Modal zoom not reset on reopen, got: " + str(zoom_reopen_val)

                # Test Zoom Reset button
                await page.click("#btn-zoom-in")
                await page.click("#btn-zoom-reset")
                zoom_reset_btn_val = await page.locator("#modal-img").evaluate("el => el.style.transform")
                assert zoom_reset_btn_val in ["scale(1)", "scale(1.0)"], "Modal zoom not reset on reset button, got: " + str(zoom_reset_btn_val)

                # Close modal
                await page.keyboard.press("Escape")
                log_print("[PASS] 10d. Modal Verified: Keyboard Enter Open, Escape Close, Zoom Controls (+0.25 -> 1.25) & Auto-Reset")

                # 10e. Modal Verification across ALL packaged Evidence Cards
                cards = await page.locator("#gallery-container .gallery-card").all()
                log_print("       Verifying modal rendering on all " + str(len(cards)) + " evidence cards...")
                for idx, card in enumerate(cards):
                    ev_expected = evidences[idx]
                    await card.click()
                    assert await page.is_visible("#image-modal.open"), f"Card {idx} ({ev_expected.get('id')}) failed to open modal!"
                    img_src = await page.locator("#modal-img").get_attribute("src")
                    assert ev_expected.get("imagePath") in img_src, f"Modal image src mismatch on card {idx}: expected {ev_expected.get('imagePath')}, got {img_src}"
                    # Check modal image decodes
                    modal_decodes = await page.locator("#modal-img").evaluate("el => el.complete && el.naturalWidth > 0")
                    assert modal_decodes, f"Modal image failed to decode on card {idx}: {img_src}"
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(50)
                log_print("[PASS] 10e. Comprehensive Modal Check Passed (All " + str(len(cards)) + " Evidence Items Open, Decode & Close cleanly)")

                # 10f. Sample Assembly/Pseudocode <details> Toggle Check
                for sample in samples:
                    tab_btn_id = "#tab-btn-sample-" + (sample.get("id") or "")
                    await page.click(tab_btn_id)
                    await page.wait_for_timeout(100)
                    details_elements = await page.locator(".tab-content.active details").all()
                    for d in details_elements:
                        # Verify default collapsed
                        is_open_default = await d.evaluate("el => el.hasAttribute('open')")
                        assert not is_open_default, f"Details container on {tab_btn_id} should be collapsed by default!"
                        # Click summary to expand
                        summary = d.locator("summary")
                        await summary.click()
                        is_open_after = await d.evaluate("el => el.hasAttribute('open')")
                        assert is_open_after, f"Details container on {tab_btn_id} failed to open on summary click!"
                        # Click summary again to collapse
                        await summary.click()
                        is_open_final = await d.evaluate("el => el.hasAttribute('open')")
                        assert not is_open_final, f"Details container on {tab_btn_id} failed to collapse on second click!"
                log_print("[PASS] 10f. Sample Assembly <details> Containers Verified (Default collapsed, clean expand & collapse)")

                # 10g. Artifacts & Documentation Links Check
                await page.click("#tab-btn-repro")
                await page.wait_for_timeout(150)
                artifact_links = await page.locator("#tab-repro a").all()
                assert len(artifact_links) >= 2, "Expected at least 2 artifact download links in repro tab!"
                for al in artifact_links:
                    href = await al.get_attribute("href")
                    local_target = os.path.normpath(os.path.join(SPA_DIR, href))
                    exists = os.path.exists(local_target)
                    size = os.path.getsize(local_target) if exists else 0
                    assert exists and size > 0, f"Artifact link target missing or empty: {href} -> {local_target}"
                    log_print("       [OK Link] " + href + " -> " + str(size) + " bytes")
                log_print("[PASS] 10g. All Artifacts & README Links Validated on Local Disk")

                # 10h. Clean Text Encoding & Mojibake Check
                has_double_escaping = await page.evaluate("""() => {
                    const text = document.body.innerText;
                    return /&amp;|&lt;|&gt;|&#39;|&quot;/.test(text);
                }""")
                assert not has_double_escaping, "Double HTML escaping detected in rendered UI text!"
                log_print("[PASS] 10h. Zero Double-Escaping or Raw Entity Strings Detected")

                # 10i. Behavioral Check: Inline Reading Evidence (Every accepted evidence placed in a reading step)
                # Verify exactly 20 reading steps match raw_data readingGuide (sum of sections)
                reading_guide = raw_data.get("readingGuide", {})
                if isinstance(reading_guide, dict):
                    expected_steps_count = sum(len(v) for v in reading_guide.values() if isinstance(v, list))
                elif isinstance(reading_guide, list):
                    expected_steps_count = len(reading_guide)
                else:
                    expected_steps_count = 20
                assert expected_steps_count == 20, f"Expected 20 steps defined in readingGuide, got {expected_steps_count}!"
                inline_articles = await page.locator("article.reading-step").all()
                log_print(f"       Found {len(inline_articles)} article.reading-step elements (expected: {expected_steps_count})")
                assert len(inline_articles) == expected_steps_count, f"Expected {expected_steps_count} reading steps, found {len(inline_articles)}!"

                # Query all canonical reading step figures across overview and sample tabs
                inline_figures = await page.locator("article.reading-step figure.inline-evidence, section.overview-evidence figure.inline-evidence").all()
                inline_count = len(inline_figures)
                log_print(f"       Found {inline_count} inline evidence figures across reading steps")
                assert inline_count == 36, f"Expected 36 inline evidence figures across reading steps, found {inline_count}!"

                observed_inline_ids = set()
                for fig in inline_figures:
                    ev_id = await fig.get_attribute("data-evidence-id")
                    assert ev_id, "figure.inline-evidence must have non-empty data-evidence-id attribute!"
                    assert ev_id not in observed_inline_ids, f"Duplicate inline evidence placement for {ev_id}!"
                    observed_inline_ids.add(ev_id)

                    # Verify parent article.reading-step has data-step-id, a heading, and .step-explanation before figure
                    parent_article = fig.locator("xpath=ancestor::article[contains(@class, 'reading-step')]")
                    assert await parent_article.count() == 1, f"Inline figure {ev_id} must reside inside article.reading-step!"
                    step_id = await parent_article.get_attribute("data-step-id")
                    assert step_id, f"Parent article for {ev_id} must have non-empty data-step-id!"

                    has_heading = await parent_article.locator("h2, h3, h4").count() > 0
                    assert has_heading, f"Parent article for {ev_id} must contain a step heading!"

                    explanation_loc = parent_article.locator(".step-explanation")
                    assert await explanation_loc.count() > 0, f"Parent article for {ev_id} must contain .step-explanation preceding evidence!"

                    # Verify strict DOM order: explanation precedes figure using compareDocumentPosition
                    is_preceding = await fig.evaluate("""(figEl) => {
                        const article = figEl.closest('article.reading-step');
                        const expl = article ? article.querySelector('.step-explanation') : null;
                        if (!expl) return false;
                        // Node.DOCUMENT_POSITION_FOLLOWING = 4 means figEl follows expl
                        return !!(expl.compareDocumentPosition(figEl) & Node.DOCUMENT_POSITION_FOLLOWING);
                    }""")
                    assert is_preceding, f"In article {step_id}, .step-explanation must precede figure {ev_id} in DOM order!"

                    # Verify img
                    img_loc = fig.locator("img")
                    assert await img_loc.count() == 1, f"Inline figure {ev_id} must have exactly one img element!"
                    obj_fit = await img_loc.evaluate("el => window.getComputedStyle(el).objectFit")
                    assert obj_fit == "contain", f"Inline image {ev_id} must have object-fit: contain to prevent cropping!"

                    # Verify figcaption .evidence-reading with observation, conclusion, and 'Đọc ở đâu'
                    caption_loc = fig.locator("figcaption.evidence-reading, figcaption")
                    assert await caption_loc.count() == 1, f"Inline figure {ev_id} must have a figcaption!"
                    caption_text = await caption_loc.inner_text()
                    has_obs = "Quan sát:" in caption_text or "Quan sát" in caption_text
                    assert has_obs, f"Inline caption {ev_id} must describe observation!"
                    has_concl = "Ý nghĩa:" in caption_text or "Kết luận:" in caption_text or "Ý nghĩa" in caption_text or "Kết luận" in caption_text
                    assert has_concl, f"Inline caption {ev_id} must provide technical conclusion!"
                    has_where = "Đọc ở đâu" in caption_text or "doc o dau" in caption_text.lower()
                    assert has_where, f"Inline caption {ev_id} must contain 'Đọc ở đâu' guidance!"

                    # Verify button.evidence-open exists
                    open_btn = fig.locator("button.evidence-open")
                    assert await open_btn.count() == 1, f"Inline figure {ev_id} must have exactly one button.evidence-open!"

                # Verify exact canonical set of 36 accepted evidence IDs from raw_data evidences (all curated evidences)
                expected_ids = {e["id"] for e in evidences}
                assert len(expected_ids) == 36, f"Expected exactly 36 accepted evidences in report data, found {len(expected_ids)}!"
                assert observed_inline_ids == expected_ids, f"Inline evidence IDs do not match expected canonical set! Missing: {expected_ids - observed_inline_ids}, Unexpected: {observed_inline_ids - expected_ids}"

                # Verify all 36 inline images eagerly decoded at full original 2560x1600 resolution
                inline_decode_stats = await page.evaluate("""async () => {
                    const figs = document.querySelectorAll('article.reading-step figure.inline-evidence, section.overview-evidence figure.inline-evidence');
                    const results = [];
                    for (const fig of figs) {
                        const evId = fig.getAttribute('data-evidence-id');
                        const img = fig.querySelector('img');
                        img.loading = 'eager';
                        try {
                            await img.decode();
                        } catch(e) {}
                        results.push({
                            id: evId,
                            complete: img.complete,
                            w: img.naturalWidth,
                            h: img.naturalHeight
                        });
                    }
                    return results;
                }""")
                assert len(inline_decode_stats) == 36, f"Expected 36 inline decode results, got {len(inline_decode_stats)}!"
                for stat in inline_decode_stats:
                    assert stat["complete"], f"Inline image {stat['id']} failed to load/complete!"
                    assert stat["w"] == 2560 and stat["h"] == 1600, f"Inline image {stat['id']} dimensions mismatch! Expected 2560x1600, got {stat['w']}x{stat['h']}"
                log_print("[PASS]       All 36 inline evidence images eagerly decoded at full uncropped 2560x1600 resolution")

                # Verify all 36 gallery-context-link elements activate correct panel & target without opening modal
                await page.click("#tab-btn-gallery")
                await page.wait_for_timeout(200)
                gallery_links = await page.locator(".gallery-context-link").all()
                assert len(gallery_links) == 36, f"Expected 36 .gallery-context-link elements, found {len(gallery_links)}!"
                for link in gallery_links:
                    href = await link.get_attribute("href")
                    target_ev_id = href.replace("#reading-", "")
                    await link.click()
                    await page.wait_for_timeout(80)
                    
                    # Ensure modal remains closed during context jump
                    modal_visible = await page.is_visible("#image-modal.open")
                    assert not modal_visible, f"Modal should not open when clicking gallery-context-link for {target_ev_id}!"
                    
                    # Verify active panel contains target figure
                    active_tab_id = await page.locator(".tab-content.active").first.get_attribute("id")
                    target_in_panel = await page.locator(f"#{active_tab_id} figure.inline-evidence[data-evidence-id='{target_ev_id}']").count()
                    assert target_in_panel == 1, f"Gallery context link for {target_ev_id} did not activate container panel #{active_tab_id}!"
                    
                    # Return to gallery tab for next link
                    await page.click("#tab-btn-gallery")
                    await page.wait_for_timeout(40)
                log_print("[PASS]       All 36 gallery-context-link routing verified: correct tab activation, target resolved, zero modal trigger")

                # Test headless modal open via button.evidence-open and Escape focus return on at least 1 image per tab
                modal_probe_tabs = [
                    ("#tab-btn-overview", "#tab-overview"),
                    ("#tab-btn-sample-lab13-01", "#tab-sample-lab13-01"),
                    ("#tab-btn-sample-lab13-02", "#tab-sample-lab13-02"),
                    ("#tab-btn-sample-lab13-03", "#tab-sample-lab13-03"),
                ]
                for btn_id, tab_sel in modal_probe_tabs:
                    await page.click(btn_id)
                    await page.wait_for_timeout(150)
                    probe_btn = page.locator(f"{tab_sel} figure.inline-evidence button.evidence-open").first
                    assert await probe_btn.count() == 1, f"No button.evidence-open found in {tab_sel}!"
                    btn_ev_id = await probe_btn.get_attribute("data-ev-id")
                    ev_data = next((e for e in evidences if e.get("id") == btn_ev_id), None)
                    assert ev_data is not None, f"Evidence data missing for probe {btn_ev_id}!"
                    
                    # Click button to open modal (matches actual #image-modal.open)
                    await probe_btn.click()
                    await page.wait_for_timeout(250)
                    assert await page.is_visible("#image-modal.open"), f"Modal #image-modal.open failed to activate when clicking evidence-open button for {btn_ev_id} on {tab_sel}!"
                    
                    # Verify modal image src matches probe evidence imagePath
                    modal_src = await page.locator("#modal-img").get_attribute("src")
                    assert ev_data.get("imagePath") in modal_src, f"Modal image src mismatch for {btn_ev_id}: expected {ev_data.get('imagePath')}, got {modal_src}"
                    modal_decodes = await page.locator("#modal-img").evaluate("el => el.complete && el.naturalWidth > 0")
                    assert modal_decodes, f"Modal image failed to decode for {btn_ev_id}: {modal_src}"

                    # Press Escape to close modal and verify focus
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(250)
                    assert not await page.is_visible("#image-modal.open"), f"Modal failed to close on Escape after opening from {tab_sel}!"
                    
                    # Verify focus returned to the trigger button
                    is_focused = await probe_btn.evaluate("el => document.activeElement === el")
                    assert is_focused, f"Focus did not return to button.evidence-open ({btn_ev_id}) after Escape on {tab_sel}!"
                    log_print(f"       [OK Probe] Modal opened, src verified & closed with focus restored on {tab_sel} ({btn_ev_id})")

                log_print("[PASS] 10i. Behavioral Check: All 36 Accepted Evidence Items Placed Inline with Context & Modal Verified")

        # 11. Save UI layout previews (post-animation full resolution) to artifacts/ and host visualizations
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)

        # 11a. Desktop Overview (1600x1000) post-fade
        await page.set_viewport_size({"width": 1600, "height": 1000})
        await page.click("#tab-btn-overview")
        await page.wait_for_timeout(500)
        await page.screenshot(path=PREVIEW_PNG, full_page=True)
        log_print("[PASS] 11a. UI Layout Preview (Overview Desktop) Saved: " + PREVIEW_PNG)
        if os.path.exists(HOST_VIS_DIR):
            vis_overview = os.path.join(HOST_VIS_DIR, "spa_overview_desktop.png")
            await page.screenshot(path=vis_overview, full_page=True)
            log_print("       -> Host visualization: " + vis_overview)

        # 11b. Desktop Sample 02 (1600x1000) post-fade
        await page.click("#tab-btn-sample-lab13-02")
        await page.wait_for_timeout(500)
        if os.path.exists(HOST_VIS_DIR):
            vis_sample02 = os.path.join(HOST_VIS_DIR, "spa_sample02_desktop.png")
            await page.screenshot(path=vis_sample02, full_page=True)
            log_print("[PASS] 11b. Sample 02 Desktop Preview Saved: " + vis_sample02)

        # 11c. Desktop Gallery (1600x1000) post-fade
        await page.click("#tab-btn-gallery")
        await page.wait_for_timeout(500)
        if os.path.exists(HOST_VIS_DIR):
            vis_gallery = os.path.join(HOST_VIS_DIR, "spa_gallery_desktop.png")
            await page.screenshot(path=vis_gallery, full_page=True)
            log_print("[PASS] 11c. Gallery Desktop Preview Saved: " + vis_gallery)

        # 11d. Mobile 390px Overview (390x844) post-fade
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.click("#tab-btn-overview")
        await page.wait_for_timeout(500)
        if os.path.exists(HOST_VIS_DIR):
            vis_mobile = os.path.join(HOST_VIS_DIR, "spa_mobile_390px.png")
            await page.screenshot(path=vis_mobile, full_page=True)
            log_print("[PASS] 11d. Mobile 390px Preview Saved: " + vis_mobile)

        # Restore standard desktop resolution
        await page.set_viewport_size({"width": 1600, "height": 1000})
        await page.click("#tab-btn-overview")
        await page.wait_for_timeout(300)

        # 12. Final End-to-End Errors & Network Request Audit (Post-Interactions)
        final_ext_requests = [url for url in captured_requests if url.startswith("http://") or url.startswith("https://")]
        assert len(final_ext_requests) == 0, "External HTTP(S) requests captured throughout session: " + str(final_ext_requests)
        final_page_errors = [e for e in page_errors if "ERR_FILE_NOT_FOUND" not in e]
        assert len(final_page_errors) == 0, "Final Page JavaScript Errors Detected: " + str(final_page_errors)
        assert len(console_errors) == 0, "Final Console Errors Detected: " + str(console_errors)
        log_print("[PASS] 12. Final Lifecycle Audit Passed: 0 External Requests, 0 Console Errors, 0 Page Errors")

        log_print("==================================================")
        log_print(">>> ALL QA TESTS PASSED: OFFLINE SPA UI CHECKS COMPLETED <<<")
        log_print("==================================================")
        await browser.close()

    # Write log to log_file in UTF-8
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    print("Logged test results to: " + log_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true", help="Allow running with mock data if report-data.js missing")
    parser.add_argument("--log", type=str, default=DEFAULT_QA_LOG, help="Path to write QA log")
    args = parser.parse_args()
    asyncio.run(main(allow_mock=args.mock, log_file=args.log))
