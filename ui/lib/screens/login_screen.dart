import 'package:flutter/material.dart';
import '../constants/colors.dart';
import '../services/api_service.dart';

/// Entry point for the app. Shows the login form; on success, hands off to
/// [onAuthenticated] so the caller (main.dart) can swap in the dashboard.
class LoginScreen extends StatefulWidget {
  final VoidCallback onAuthenticated;
  /// True when this screen is being shown because the user's session
  /// expired mid-use (a 401 from an authenticated call), rather than a
  /// normal cold-start login. Shows a one-time explanatory banner instead
  /// of leaving the redirect unexplained.
  final bool sessionExpired;
  const LoginScreen({
    super.key,
    required this.onAuthenticated,
    this.sessionExpired = false,
  });

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _tenantNameController = TextEditingController();

  bool _isRegisterMode = false;
  bool _isLoading = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    if (widget.sessionExpired) {
      _errorMessage = 'Your session expired. Please log in again.';
    }
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _tenantNameController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      if (_isRegisterMode) {
        await ApiService.register(
          _emailController.text.trim(),
          _passwordController.text,
          _tenantNameController.text.trim(),
        );
      } else {
        await ApiService.login(
          _emailController.text.trim(),
          _passwordController.text,
        );
      }
      if (!mounted) return;
      widget.onAuthenticated();
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _fillDemoCredentials() {
    _emailController.text = 'demo@graphrisk.dev';
    _passwordController.text = 'demopass123';
    setState(() => _isRegisterMode = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: kBackground,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _buildHeader(),
                const SizedBox(height: 32),
                _buildCard(),
                const SizedBox(height: 20),
                _buildDemoLink(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      children: [
        Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [kAccent, kMidBlue],
            ),
            borderRadius: BorderRadius.circular(14),
          ),
          child: const Icon(Icons.hub_outlined, color: Colors.white, size: 28),
        ),
        const SizedBox(height: 16),
        const Text(
          'GraphRisk',
          style: TextStyle(
            color: Colors.white,
            fontSize: 26,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.5,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          'Risk is a network, not a list.',
          style: TextStyle(color: Colors.white.withOpacity(0.5), fontSize: 14),
        ),
      ],
    );
  }

  Widget _buildCard() {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: kSurface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: kSurface2),
      ),
      child: Form(
        key: _formKey,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildModeToggle(),
            const SizedBox(height: 20),
            if (_isRegisterMode) ...[
              _buildField(
                controller: _tenantNameController,
                label: 'Organization name',
                icon: Icons.business_outlined,
                validator: (v) => (v == null || v.trim().isEmpty) ? 'Enter an organization name' : null,
              ),
              const SizedBox(height: 14),
            ],
            _buildField(
              controller: _emailController,
              label: 'Email',
              icon: Icons.mail_outline,
              keyboardType: TextInputType.emailAddress,
              validator: (v) => (v == null || !v.contains('@')) ? 'Enter a valid email' : null,
            ),
            const SizedBox(height: 14),
            _buildField(
              controller: _passwordController,
              label: 'Password',
              icon: Icons.lock_outline,
              obscureText: true,
              validator: (v) => (v == null || v.length < 8) ? 'At least 8 characters' : null,
            ),
            if (_errorMessage != null) ...[
              const SizedBox(height: 14),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: kRed.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: kRed.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.error_outline, color: kRed, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(_errorMessage!, style: const TextStyle(color: kRed, fontSize: 13)),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 20),
            SizedBox(
              height: 48,
              child: ElevatedButton(
                onPressed: _isLoading ? null : _submit,
                style: ElevatedButton.styleFrom(
                  backgroundColor: kAccent,
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                  elevation: 0,
                ),
                child: _isLoading
                    ? const SizedBox(
                        width: 20, height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                      )
                    : Text(
                        _isRegisterMode ? 'Create account' : 'Log in',
                        style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
                      ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildModeToggle() {
    return Row(
      children: [
        Expanded(child: _buildToggleTab('Log in', !_isRegisterMode, () => setState(() => _isRegisterMode = false))),
        const SizedBox(width: 8),
        Expanded(child: _buildToggleTab('Create account', _isRegisterMode, () => setState(() => _isRegisterMode = true))),
      ],
    );
  }

  Widget _buildToggleTab(String label, bool active, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: active ? kAccent.withOpacity(0.15) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: active ? kAccent : kSurface2),
        ),
        child: Text(
          label,
          textAlign: TextAlign.center,
          style: TextStyle(
            color: active ? kAccent : Colors.white.withOpacity(0.6),
            fontWeight: FontWeight.w600,
            fontSize: 13,
          ),
        ),
      ),
    );
  }

  Widget _buildField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    bool obscureText = false,
    TextInputType? keyboardType,
    String? Function(String?)? validator,
  }) {
    return TextFormField(
      controller: controller,
      obscureText: obscureText,
      keyboardType: keyboardType,
      validator: validator,
      style: const TextStyle(color: Colors.white, fontSize: 14),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: TextStyle(color: Colors.white.withOpacity(0.5), fontSize: 14),
        prefixIcon: Icon(icon, color: Colors.white.withOpacity(0.4), size: 20),
        filled: true,
        fillColor: kSurface2.withOpacity(0.4),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: kAccent, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: kRed, width: 1),
        ),
      ),
    );
  }

  Widget _buildDemoLink() {
    return Center(
      child: TextButton.icon(
        onPressed: _fillDemoCredentials,
        icon: Icon(Icons.play_circle_outline, size: 16, color: Colors.white.withOpacity(0.5)),
        label: Text(
          'Use demo credentials',
          style: TextStyle(color: Colors.white.withOpacity(0.5), fontSize: 13),
        ),
      ),
    );
  }
}
