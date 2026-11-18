"""Picture scam shield (fix round, review OC-2): everyday bills, receipts, flyers and notices are a hard
negative set. None of them may be called "likely scam" (HIGH), like the everyday chat sets for the rules.

The first seven are the outside reviewer's samples (reviews/modelcheck-ocr-review-2026-11-17.md); the rest
are written for this gate in Chinese and English, in the shapes OCR returns (line breaks, short lines).
All names, numbers and addresses are made up.
"""
from __future__ import annotations

import time
import unittest

from hearthward_guard.threshold import scam

REVIEWER = [
    "City Water Utility\nAccount 4471-22\nAmount due: $84.20\nDue date: Dec 5\nLate fees apply after the due "
    "date.\nQuestions? Call 555-0134",
    "Pharmacy receipt\nAmoxicillin 500mg $12.40\nTake immediately after meals\nQuestions call 555-0199",
    "Library notice: 2 books overdue. Late fees $0.25/day. Renew online or call 555-0123",
    "物业缴费通知：请于本月30日前缴纳物业费，逾期将收取滞纳金。联系电话：000-5550134 金额：320元",
    "超市特惠 仅限今天 鸡蛋 ¥9.9 立即抢购 热线 000-5550145",
    "社区通知：疫苗接种 免费 请携带身份证 工作人员会联系您 电话 000-5550138",
    "Congratulations to our team winner of the science fair! Prize: $50 gift card. Contact Ms. Lee 555-0177",
]

EVERYDAY_EN = [
    "Prairie Electric Co-op\nStatement date 11/02\nAccount number 55-1902\nPrevious balance $0.00\nCurrent charges "
    "$96.14\nAmount due $96.14 by 11/25\nPay online at prairie-electric.example.com or call 555-0101\nA late "
    "fee of 1.5% applies to unpaid balances.",
    "FINAL NOTICE\nYour library card balance of $3.75 is overdue. Please pay at the front desk to avoid late fees.\n"
    "Main Street Library 555-0150",
    "Sunrise Family Dentistry\nAppointment reminder: Tue Nov 18, 2:30 PM\nPlease call 555-0188 at least 24 "
    "hours ahead if you need to reschedule. A $25 fee applies to missed appointments.",
    "Fresh Mart receipt\nBananas 1.29\nMilk 3.49\nEggs 4.19\nSubtotal 8.97\nTax 0.36\nTotal $9.33\nVisa ****1234 "
    "APPROVED\nThank you! Returns within 30 days with receipt.",
    "WEEKEND SALE - TODAY ONLY!\n50% off all winter coats\nHurry, while supplies last\nStore hours 9-9\nCall "
    "555-0111 for directions",
    "Lincoln Elementary\nField trip permission slip\nPlease return by Friday with $8 for the bus.\nQuestions? "
    "Contact the front office 555-0122",
    "Riverbend Gas\nPayment received - thank you!\nAmount paid $54.80\nConfirmation 88213\nYour next bill will "
    "be mailed on Dec 1.",
    "Parking citation\nViolation: expired meter\nFine: $35.00\nPay within 30 days to avoid a penalty.\nPay by mail "
    "or at the city clerk's office. Info: 555-0166",
    "Pharmacy refill ready\nYour prescription is ready for pickup at Oak St Pharmacy.\nPickup within 7 days.\nCall "
    "us at 555-0177 with questions.",
    "Community blood drive\nSaturday 9am-1pm at the rec center\nFree snacks for every donor\nSign up: call "
    "555-0144",
    "County Treasurer\nProperty tax bill 2026\nFirst installment due Dec 10: $1,204.50\nPay online at "
    "treasurer.example.gov or by mail. Penalty of 1% per month after the due date.",
    "Your package was delivered\nOrder #4471 left at front door, 3:12 PM\nQuestions? Visit help.shop.example.com",
    "Raffle winners! Congratulations to Maria G. who won the quilt. Thank you to everyone who bought tickets for "
    "the church fundraiser.",
    "Car wash coupon\nFull service $12.99 - offer expires soon\nScan the QR code for a map\n1820 Elm Road",
    "Internet service notice\nScheduled maintenance tonight 1-3 AM. Service may be on hold briefly. No action "
    "needed. Support: 555-0199",
    "Fraud alert from your bank: we will never ask you to move money to a safe account or to read us a code.",
    "Corner Cafe rewards\nScan the QR code to receive your $5 reward on your next visit.\nValid until Dec 31.",
    "Doctor's office\nLab results are ready. Log in to the patient portal to view them, or call 555-0133.",
]

EVERYDAY_ZH = [
    "国网电费通知\n户号：00012345\n本期电费：156.30元\n请于12月15日前缴纳，逾期将产生违约金。\n客服电话：95598",
    "自来水公司缴费提醒\n户名：王**\n应缴金额：48.60元\n可通过银行或营业厅缴费。咨询电话：000-5550123",
    "小区停水通知\n因管道维修，明天上午9点至下午3点停水，请提前储水。\n物业服务中心 电话：000-5550199",
    "超市小票\n大米 5kg 39.90\n鸡蛋 12.80\n牛奶 25.60\n合计：78.30元\n微信支付\n谢谢惠顾，欢迎再次光临",
    "药店收据\n阿莫西林胶囊 1盒 18.50元\n用法：饭后立即服用，一日三次\n如有疑问请致电 000-5550188",
    "幼儿园通知\n下周三组织春游，请家长于周五前交纳活动费50元，并签署回执。\n联系人：张老师 000-5550139",
    "社区通知\n本周六上午在社区活动中心免费量血压、测血糖，请携带医保卡。\n工作人员将电话通知各位老人。",
    "快递取件通知\n您的包裹已到小区驿站，取件码 3-2-1108，请尽快领取。\n驿站电话：000-5550137",
    "银行账单\n本期应还金额：2,345.00元\n最后还款日：12月8日\n可通过手机银行还款。客服热线：95588",
    "医院预约提醒\n您已预约11月20日上午内科门诊，请提前15分钟到达并携带身份证。\n如需取消请拨打 000-5550177",
    "宽带续费提醒\n您的宽带将于12月1日到期，请及时续费，否则将暂停服务。\n营业厅地址：人民路12号\n客服：10000",
    "商场促销\n双十一大促 全场五折 仅限今天\n会员积分翻倍\n详情咨询 000-5550146",
    "学校通知\n恭喜三年级二班在合唱比赛中获得一等奖！奖品已发放到班级。\n教务处",
    "燃气公司\n安全检查通知：工作人员将于本周入户检查燃气设备，请留意工作证。\n咨询电话 000-5550166",
    "停车缴费\n车牌 京A12345\n停车时长 2小时\n应付金额 10.00元\n请扫码支付",
    "银行提醒：我行不会要求您把资金转入所谓的安全账户，也不会索要验证码。",
    "社保局通知\n2027年度城乡居民医保开始缴费，请于12月31日前通过银行或社区缴纳。咨询电话：12333",
]


class TestEverydayPicturesAreNotScams(unittest.TestCase):
    def check(self, texts):
        high = [t[:50] for t in texts if scam.assess(t).level == "high"]
        self.assertEqual(high, [], f"{len(high)}/{len(texts)} everyday pictures called 'likely scam': {high}")

    def test_reviewer_samples(self):
        self.check(REVIEWER)

    def test_english_bills_receipts_flyers(self):
        self.check(EVERYDAY_EN)

    def test_chinese_bills_receipts_flyers(self):
        self.check(EVERYDAY_ZH)

    def test_scams_still_caught(self):
        """Controls: the same shapes with a real scam ask stay 'likely scam'."""
        for t in ("City Water Utility: your service will be cut off today. Pay the $84.20 reconnection balance "
                  "with Google Play gift cards and send the card numbers to 555-0134.",
                  "This is the IRS. A warrant has been issued for your arrest. Call 555-0134 now.",
                  "Your account has been suspended. Verify your account at https://secure-login.example.invalid/x",
                  "国网客服：您的账户已冻结，请将电费转账到安全账户，否则将被起诉。",
                  "恭喜您中奖！扫码领取 https://example.invalid/a1 奖金 5000 元",
                  "Package on hold: pay the $1.99 redelivery fee at https://example.invalid/a1",
                  "Grandma, it's me. I'm in jail and need bail money. Please don't tell mom."):
            self.assertEqual(scam.assess(t).level, "high", t)


class TestFixturePhonesAreFake(unittest.TestCase):
    """Fixture phone numbers are fictional shapes only: US 555-0100..0199; Chinese texts use 000-55501xx
    (area code 000 does not exist; the 555-01xx fiction range after it), never a real-looking mobile, city
    or 400/800 number. Public service numbers (95598, 12333) may stay. The fake shapes must still count as
    phone numbers for the scam rules, and stay clear of leakcheck's phone shapes (3-3-4 with separators)."""

    def test_only_fake_shapes(self):
        for t in REVIEWER + EVERYDAY_EN + EVERYDAY_ZH:
            for m in scam._PHONE_RE.finditer(t):
                self.assertRegex(m.group(0), r"^(?:000-55501\d\d|555-01\d\d)$", t[:40])

    def test_fake_shapes_count_as_phones(self):
        for t in ("咨询电话：000-5550123", "联系人：张老师 000-5550139", "Questions? Call 555-0134"):
            self.assertEqual(scam.assess(t).indicators.get("phones"), 1, t)


class TestScamSpeed(unittest.TestCase):
    """Review OC-6: every indicator pattern is linear; 20,000 characters of any shape well under 0.5 s."""

    def test_adversarial_shapes(self):
        shapes = ["aa." * 6667, "1," * 10000, "1" * 20000, "a-" * 10000, "a." * 9000 + "@", "a@" * 10000,
                  "www." * 5000, "http://" + "a." * 9000, "$" + "1," * 9999, "一" * 20000 + "元", "x.y" * 6000,
                  "verify " * 2800, "pay " * 5000]
        for s in shapes:
            t0 = time.perf_counter()
            scam.assess(s)
            self.assertLess(time.perf_counter() - t0, 0.5, s[:12])


if __name__ == "__main__":
    unittest.main()
