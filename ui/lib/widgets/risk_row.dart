import 'package:flutter/material.dart';
import '../constants/colors.dart';

class RiskRow extends StatelessWidget {
  final String title;
  final double score;
  final int    likelihood;
  final int    impact;

  const RiskRow({super.key, required this.title,
                 required this.score, required this.likelihood, required this.impact});

  Color get _scoreColor {
    if (score >= 20) return kRed;
    if (score >= 12) return kOrange;
    return kGreen;
  }

  @override
  Widget build(BuildContext context) {
    final detail = 'Likelihood: ' + likelihood.toString() + '  -  Impact: ' + impact.toString();
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: kSurface2,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _scoreColor.withOpacity(0.3)),
      ),
      child: Row(children: [
        Container(
          width: 48, height: 48,
          decoration: BoxDecoration(
            color: _scoreColor.withOpacity(0.15),
            borderRadius: BorderRadius.circular(8)),
          child: Center(child: Text(score.toInt().toString(),
              style: TextStyle(color: _scoreColor, fontWeight: FontWeight.bold, fontSize: 18))),
        ),
        const SizedBox(width: 16),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w500)),
          const SizedBox(height: 4),
          Text(detail, style: const TextStyle(color: Colors.white54, fontSize: 12)),
        ])),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: _scoreColor.withOpacity(0.15),
            borderRadius: BorderRadius.circular(20)),
          child: Text(score >= 20 ? 'Critical' : score >= 12 ? 'High' : 'Medium',
              style: TextStyle(color: _scoreColor, fontSize: 11, fontWeight: FontWeight.bold)),
        ),
      ]),
    );
  }
}
