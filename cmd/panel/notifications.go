package main

import (
	"fmt"
	"strconv"
	"strings"
)

func formatTraffic(n int64) string {
	if n <= 0 {
		return "0 Б"
	}
	units := []string{"Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ", "ЭБ"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	precision := 2
	if v >= 100 {
		precision = 0
	} else if v >= 10 {
		precision = 1
	}
	value := strconv.FormatFloat(v, 'f', precision, 64)
	if strings.Contains(value, ".") {
		value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	}
	return strings.ReplaceAll(value, ".", ",") + " " + units[i]
}

func formatPercent(used, limit int64) string {
	if limit <= 0 {
		return "0%"
	}
	p := float64(used) * 100 / float64(limit)
	value := strconv.FormatFloat(p, 'f', 1, 64)
	value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	return strings.ReplaceAll(value, ".", ",") + "%"
}

func quotaReachedThreshold(used, limit int64, threshold int) bool {
	return limit > 0 && float64(used)*100 >= float64(limit)*float64(threshold)
}

func rearmQuota(p *Period, limit int64, threshold int) {
	if limit <= 0 || p.Used < limit {
		p.ExhaustedSent = false
	}
	if limit <= 0 || !quotaReachedThreshold(p.Used, limit, threshold) {
		p.ThresholdSent = false
	}
}

func quotaName(kind string) string {
	if kind == "daily" {
		return "дневной"
	}
	return "месячной"
}
func quotaTitle(kind string) string {
	if kind == "daily" {
		return "Дневная"
	}
	return "Месячная"
}

func quotaThresholdMessage(kind string, used, limit int64) string {
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("Достигнут порог %s квоты — %s (%s из %s), осталось %s.", quotaName(kind), formatPercent(used, limit), formatTraffic(used), formatTraffic(limit), formatTraffic(remaining))
}

func quotaExhaustedMessage(kind string, used, limit int64) string {
	return fmt.Sprintf("%s квота исчерпана — использовано %s из %s (%s). Трафик приостановлен до пополнения или сброса квоты.", quotaTitle(kind), formatTraffic(used), formatTraffic(limit), formatPercent(used, limit))
}

func quotaTopupMessage(kind string, added, oldLimit, newLimit, used int64) string {
	remaining := newLimit - used
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("Пополнение %s квоты: +%s. Лимит: %s → %s. Использовано %s из %s (%s), осталось %s.", quotaName(kind), formatTraffic(added), formatTraffic(oldLimit), formatTraffic(newLimit), formatTraffic(used), formatTraffic(newLimit), formatPercent(used, newLimit), formatTraffic(remaining))
}

func quotaResetMessage(kind string, limit int64) string {
	return fmt.Sprintf("%s квота сброшена — новый лимит %s, использовано 0.", quotaTitle(kind), formatTraffic(limit))
}
