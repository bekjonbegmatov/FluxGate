package main

import "testing"

func TestTrafficNotificationFormatting(t *testing.T) {
	const gb int64 = 1 << 30
	const tb int64 = 1 << 40
	if got := formatTraffic(gb); got != "1 ГБ" {
		t.Fatalf("1 GiB: %q", got)
	}
	if got := formatTraffic(tb); got != "1 ТБ" {
		t.Fatalf("1 TiB: %q", got)
	}
	if got := formatTraffic(3 * gb / 2); got != "1,5 ГБ" {
		t.Fatalf("1.5 GiB: %q", got)
	}
	threshold := quotaThresholdMessage("daily", 10*gb, 12*gb)
	if want := "Достигнут порог дневной квоты — 83,3% (10 ГБ из 12 ГБ), осталось 2 ГБ."; threshold != want {
		t.Fatalf("threshold: %q", threshold)
	}
	exhausted := quotaExhaustedMessage("daily", 12*gb, 12*gb)
	if want := "Дневная квота исчерпана — использовано 12 ГБ из 12 ГБ (100%). Трафик приостановлен до пополнения или сброса квоты."; exhausted != want {
		t.Fatalf("exhausted: %q", exhausted)
	}
	topup := quotaTopupMessage("daily", gb, 12*gb, 13*gb, 10*gb)
	if want := "Пополнение дневной квоты: +1 ГБ. Лимит: 12 ГБ → 13 ГБ. Использовано 10 ГБ из 13 ГБ (76,9%), осталось 3 ГБ."; topup != want {
		t.Fatalf("topup: %q", topup)
	}
}

func TestThresholdDoesNotOverflowLargeQuota(t *testing.T) {
	limit := int64(1 << 60)
	if !quotaReachedThreshold(limit/10*8, limit, 80) {
		t.Fatal("80% threshold should be reached")
	}
	if quotaReachedThreshold(limit/10*7, limit, 80) {
		t.Fatal("80% threshold should not be reached")
	}
}

func TestTopupRearmsNotifications(t *testing.T) {
	const gb int64 = 1 << 30
	p := Period{Used: 12 * gb, ThresholdSent: true, ExhaustedSent: true}
	rearmQuota(&p, 13*gb, 80)
	if p.ExhaustedSent || !p.ThresholdSent {
		t.Fatalf("small topup: %+v", p)
	}
	rearmQuota(&p, 20*gb, 80)
	if p.ExhaustedSent || p.ThresholdSent {
		t.Fatalf("large topup: %+v", p)
	}
}
