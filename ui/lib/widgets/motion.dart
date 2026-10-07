import 'dart:async';
import 'dart:ui' show FontFeature;
import 'package:flutter/material.dart';
import '../constants/colors.dart';

/// Shared motion for the whole app.
///
/// Rules every helper here follows:
///   * Short and one-shot: an animation plays once when something appears
///     or changes, then the widget is static. The only exception is the
///     skeleton pulse, which runs only while a page is still loading.
///   * Built-in Flutter animation only -- no packages, no image/video
///     assets, so the download size and Firebase bandwidth don't change.
///   * Honours the OS "reduce motion" setting: when it's on, everything
///     shows in its final state immediately.
///   * Never wraps a decorated card in a scale Transform -- that bleeds the
///     card's fill across the window on Flutter web (CanvasKit). Fades and
///     small translations are safe and are all this file uses.
class Motion {
  Motion._();

  static const fast = Duration(milliseconds: 180);
  static const medium = Duration(milliseconds: 320);
  static const slow = Duration(milliseconds: 700);
  static const curve = Curves.easeOutCubic;

  /// Gap between items in a staggered list.
  static const staggerStep = Duration(milliseconds: 55);

  /// Only the first few rows of a list animate in; the rest just appear, so
  /// a long list (hundreds of CVEs) costs nothing extra.
  static const staggerLimit = 8;

  /// True when the user asked the OS to reduce motion.
  static bool reduced(BuildContext context) =>
      MediaQuery.maybeOf(context)?.disableAnimations ?? false;
}

/// Text whose whole numbers count up from 0 the first time it's shown.
/// Works on any string: "3", "14242", "2/4". Re-showing the same value
/// doesn't replay it; a new value animates from 0 again.
class CountUpText extends StatelessWidget {
  final String value;
  final TextStyle? style;
  final Duration duration;

  const CountUpText(this.value, {super.key, this.style, this.duration = Motion.slow});

  static final _number = RegExp(r'\d+');

  @override
  Widget build(BuildContext context) {
    // Tabular figures keep the width steady while the digits change.
    final s = (style ?? const TextStyle()).copyWith(
      fontFeatures: const [FontFeature.tabularFigures()],
    );
    if (Motion.reduced(context) || !_number.hasMatch(value)) {
      return Text(value, style: s);
    }
    return TweenAnimationBuilder<double>(
      key: ValueKey(value),
      tween: Tween(begin: 0, end: 1),
      duration: duration,
      curve: Motion.curve,
      builder: (context, t, _) => Text(
        value.replaceAllMapped(
          _number,
          (m) => (int.parse(m.group(0)!) * t).round().toString(),
        ),
        style: s,
      ),
    );
  }
}

/// A rounded progress bar that fills from 0 when first shown and glides to
/// any new value afterwards.
class AnimatedBar extends StatelessWidget {
  final double value;
  final Color color;
  final Color background;
  final double height;

  const AnimatedBar({
    super.key,
    required this.value,
    required this.color,
    this.background = kSurface2,
    this.height = 6,
  });

  @override
  Widget build(BuildContext context) {
    final double target = value.isNaN ? 0.0 : value.clamp(0.0, 1.0).toDouble();
    Widget bar(double v) => ClipRRect(
          borderRadius: BorderRadius.circular(height),
          child: LinearProgressIndicator(
            value: v,
            minHeight: height,
            backgroundColor: background,
            valueColor: AlwaysStoppedAnimation(color),
          ),
        );
    if (Motion.reduced(context)) return bar(target);
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: target),
      duration: Motion.slow,
      curve: Motion.curve,
      builder: (context, v, _) => bar(v),
    );
  }
}

/// Fades a child in while it rises a few pixels, after an optional delay.
class FadeSlideIn extends StatefulWidget {
  final Widget child;
  final Duration delay;
  final Duration duration;

  /// How far below its resting place the child starts, in logical pixels.
  final double rise;

  const FadeSlideIn({
    super.key,
    required this.child,
    this.delay = Duration.zero,
    this.duration = Motion.medium,
    this.rise = 10,
  });

  @override
  State<FadeSlideIn> createState() => _FadeSlideInState();
}

class _FadeSlideInState extends State<FadeSlideIn> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: widget.duration);
  late final Animation<double> _t = CurvedAnimation(parent: _c, curve: Motion.curve);
  Timer? _timer;
  bool _started = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_started) return;
    _started = true;
    if (Motion.reduced(context)) {
      _c.value = 1;
    } else if (widget.delay == Duration.zero) {
      _c.forward();
    } else {
      _timer = Timer(widget.delay, () {
        if (mounted) _c.forward();
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _t,
      child: widget.child,
      builder: (context, child) => Opacity(
        opacity: _t.value,
        child: Transform.translate(
          offset: Offset(0, (1 - _t.value) * widget.rise),
          child: child,
        ),
      ),
    );
  }
}

/// Wraps the [index]th item of a list so the first few items arrive one
/// after another. Items past [Motion.staggerLimit] are returned unchanged.
Widget staggerIn(int index, Widget child, {Duration start = Duration.zero}) {
  if (index >= Motion.staggerLimit) return child;
  return FadeSlideIn(delay: start + Motion.staggerStep * index, child: child);
}

/// A name that glides from a list row into the header of its detail page.
/// Both ends use the same [tag]; the text style blends from one end's size
/// to the other's during the flight, so nothing jumps or wraps.
class HeroText extends StatelessWidget {
  final Object tag;
  final String text;
  final TextStyle style;

  const HeroText({super.key, required this.tag, required this.text, required this.style});

  @override
  Widget build(BuildContext context) {
    return Hero(
      tag: tag,
      flightShuttleBuilder: (context, animation, direction, fromContext, toContext) {
        final from = ((fromContext.widget as Hero).child as _HeroTextBody).style;
        final to = ((toContext.widget as Hero).child as _HeroTextBody).style;
        return AnimatedBuilder(
          animation: animation,
          builder: (context, _) => _HeroTextBody(
            text: text,
            style: TextStyle.lerp(from, to, Motion.curve.transform(animation.value))!,
          ),
        );
      },
      child: _HeroTextBody(text: text, style: style),
    );
  }
}

class _HeroTextBody extends StatelessWidget {
  final String text;
  final TextStyle style;
  const _HeroTextBody({required this.text, required this.style});

  @override
  Widget build(BuildContext context) {
    // Material gives the text a proper DefaultTextStyle while in flight
    // (otherwise it renders with the yellow-underline debug style).
    return Material(
      type: MaterialType.transparency,
      child: FittedBox(
        fit: BoxFit.scaleDown,
        alignment: Alignment.centerLeft,
        child: Text(text, style: style, maxLines: 1, softWrap: false),
      ),
    );
  }
}

// ── Skeleton loading ─────────────────────────────────────────────────────────

/// Page shapes the skeleton can take, matching the real layouts closely
/// enough that content replaces it without the page jumping around.
enum SkeletonLayout { dashboard, list, detail, cascade }

/// Grey placeholder blocks shaped like the page that's loading, with a slow
/// pulse. After a few seconds it adds a note explaining the wait: the free
/// backend sleeps when idle and takes up to a minute to wake.
class PageSkeleton extends StatefulWidget {
  final SkeletonLayout layout;

  /// Show the "waking up the server" note after this long. Null = never.
  final Duration? slowAfter;

  /// Wrap in its own padding and scroll view. False when the caller already
  /// provides those (e.g. a skeleton under an existing page header).
  final bool standalone;

  const PageSkeleton({
    super.key,
    this.layout = SkeletonLayout.list,
    this.slowAfter = const Duration(seconds: 5),
    this.standalone = true,
  });

  @override
  State<PageSkeleton> createState() => _PageSkeletonState();
}

class _PageSkeletonState extends State<PageSkeleton> with SingleTickerProviderStateMixin {
  late final AnimationController _pulse =
      AnimationController(vsync: this, duration: const Duration(milliseconds: 1100));
  Timer? _slowTimer;
  bool _slow = false;
  bool _started = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_started) return;
    _started = true;
    if (Motion.reduced(context)) {
      _pulse.value = 0.6;
    } else {
      _pulse.repeat(reverse: true);
    }
    final after = widget.slowAfter;
    if (after != null) {
      _slowTimer = Timer(after, () {
        if (mounted) setState(() => _slow = true);
      });
    }
  }

  @override
  void dispose() {
    _slowTimer?.cancel();
    _pulse.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final blocks = FadeTransition(
      opacity: Tween<double>(begin: 0.45, end: 0.9).animate(_pulse),
      child: switch (widget.layout) {
        SkeletonLayout.dashboard => const _DashboardShape(),
        SkeletonLayout.list => const _ListShape(),
        SkeletonLayout.detail => const _DetailShape(),
        SkeletonLayout.cascade => const _CascadeShape(),
      },
    );

    final body = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        AnimatedSize(
          duration: Motion.medium,
          curve: Motion.curve,
          alignment: Alignment.topCenter,
          child: _slow ? const FadeSlideIn(child: WakingNote()) : const SizedBox(width: double.infinity),
        ),
        blocks,
      ],
    );

    if (!widget.standalone) return body;
    return SingleChildScrollView(
      physics: const NeverScrollableScrollPhysics(),
      padding: const EdgeInsets.all(24),
      child: body,
    );
  }
}

/// "The server is waking up" note, used by the skeleton and the login button.
class WakingNote extends StatelessWidget {
  const WakingNote({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: kAccent.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: kAccent.withOpacity(0.25)),
      ),
      child: const Row(children: [
        Icon(Icons.hourglass_top_rounded, color: kAccent, size: 16),
        SizedBox(width: 10),
        Expanded(
          child: Text(
            'Waking up the server. The first load after a quiet spell can take up to a minute.',
            style: TextStyle(color: Colors.white70, fontSize: 12, height: 1.4),
          ),
        ),
      ]),
    );
  }
}

class _Block extends StatelessWidget {
  final double? width;
  final double height;
  final double radius;
  const _Block({this.width, required this.height, this.radius = 6});

  @override
  Widget build(BuildContext context) => Container(
        width: width,
        height: height,
        decoration: BoxDecoration(color: kSurface2, borderRadius: BorderRadius.circular(radius)),
      );
}

class _Card extends StatelessWidget {
  final double height;
  final Widget? child;
  const _Card({required this.height, this.child});

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        height: height,
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: kSurface, borderRadius: BorderRadius.circular(12)),
        child: child,
      );
}

class _TitleShape extends StatelessWidget {
  const _TitleShape();
  @override
  Widget build(BuildContext context) => const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Block(width: 220, height: 22),
          SizedBox(height: 8),
          _Block(width: 320, height: 12),
          SizedBox(height: 24),
        ],
      );
}

class _RowShape extends StatelessWidget {
  const _RowShape();
  @override
  Widget build(BuildContext context) => const _Card(
        height: 72,
        child: Row(children: [
          _Block(width: 40, height: 40, radius: 8),
          SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _Block(width: 160, height: 12),
                SizedBox(height: 8),
                _Block(width: 240, height: 10),
              ],
            ),
          ),
        ]),
      );
}

class _ListShape extends StatelessWidget {
  const _ListShape();
  @override
  Widget build(BuildContext context) => const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [_TitleShape(), _RowShape(), _RowShape(), _RowShape(), _RowShape(), _RowShape()],
      );
}

class _DashboardShape extends StatelessWidget {
  const _DashboardShape();
  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const _TitleShape(),
      LayoutBuilder(builder: (context, c) {
        final cols = c.maxWidth > 800 ? 4 : c.maxWidth > 500 ? 2 : 1;
        final w = (c.maxWidth - (cols - 1) * 16) / cols;
        return Wrap(spacing: 16, runSpacing: 16, children: [
          for (var i = 0; i < 4; i++)
            SizedBox(
              width: w,
              child: const _Card(
                height: 130,
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  _Block(width: 90, height: 12),
                  SizedBox(height: 18),
                  _Block(width: 70, height: 26),
                  SizedBox(height: 10),
                  _Block(width: 110, height: 10),
                ]),
              ),
            ),
        ]);
      }),
      const SizedBox(height: 32),
      const _Block(width: 180, height: 16),
      const SizedBox(height: 14),
      const _RowShape(),
      const _RowShape(),
      const _RowShape(),
    ]);
  }
}

class _DetailShape extends StatelessWidget {
  const _DetailShape();
  @override
  Widget build(BuildContext context) => const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Block(width: 260, height: 12),
          SizedBox(height: 14),
          Row(children: [_Block(width: 90, height: 22, radius: 11), SizedBox(width: 6), _Block(width: 120, height: 22, radius: 11)]),
          SizedBox(height: 20),
          _Card(height: 170),
          _Card(height: 130),
          _Card(height: 150),
        ],
      );
}

class _CascadeShape extends StatelessWidget {
  const _CascadeShape();
  @override
  Widget build(BuildContext context) => const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Card(height: 96),
          SizedBox(height: 24),
          _Card(height: 64),
          SizedBox(height: 24),
          _Card(height: 64),
          SizedBox(height: 24),
          _Card(height: 64),
        ],
      );
}
