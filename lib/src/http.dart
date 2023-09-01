import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:ntlm/src/messages/messages.dart';

const _wwwAuthenticateHeader = 'www-authenticate';
const _authorizationHeader = 'authorization';

class NTLMClient extends DioForNative {
  /// The NT domain used by this client to authenticate
  String domain;

  /// The NT workstation used by this client to authenticate
  String workstation;

  /// The username of the user trying to authenticate
  String username;

  /// The password of the user trying to authenticate
  String? password;

  /// The lan manager hash of the user's password
  String? lmPassword;

  /// The NT hash of the user's password
  String? ntPassword;

  /// The prefix for 'www-authenticate'/'authorization' headers (usually
  /// either [kHeaderPrefixNTLM] or [kHeaderPrefixNegotiate])
  String headerPrefix;

  /// The HTTP client used by this NTLMClient to make requests
  late final Dio _inner;

  /// Creates a new NTLM client
  ///
  /// The [username] is required as is either the [password]...
  ///
  /// ```dart
  /// NTLMClient client = new NTLMClient(
  ///   username: "User208",
  ///   password: "password",
  /// );
  /// ```
  ///
  /// ...or the [lmPassword] and the [ntPassword] in base 64 form.
  ///
  /// ```dart
  /// String lmPassword = lmHash("password");
  /// String ntPassword = ntHash("password");
  ///
  /// NTLMClient client = new NTLMClient(
  ///   username: "User208",
  ///   lmPassword: lmPassword,
  ///   ntPassword: ntPassword,
  /// );
  /// ```
  ///
  /// You can optionally pass in an [inner] client to make all the HTTP
  /// requests.
  NTLMClient({
    this.domain = '',
    this.workstation = '',
    required this.username,
    this.password,
    this.lmPassword,
    this.ntPassword,
    Dio? inner,
    this.headerPrefix = kHeaderPrefixNTLM,
  }) {
    if (password == null && (lmPassword == null || ntPassword == null)) {
      throw ArgumentError(
        'You must provide a password or the LM and NT hash of a password.',
      );
    }

    _inner = inner ?? Dio();
  }

  /// Function that actually does the NTLM authentication.
  ///
  /// This function generates the headers required to authenticate based on
  /// previous responses.
  @override
  Future<Response<T>> fetch<T>(RequestOptions requestOptions) async {
    // 1. Send the initial request
    final msg1 = createType1Message(
      domain: domain,
      workstation: workstation,
    );

    final res2 = await _inner.fetch<T>(
      requestOptions
        ..headers[_authorizationHeader] = msg1
        ..validateStatus = (status) => true,
    );

    // 2. Parse the Type 2 message
    final res2Authenticate = res2.headers.value(_wwwAuthenticateHeader);
    // If the initial request was successful or this isn't an NTLM request,
    // return the initial response
    if (res2.statusCode == 200 || res2Authenticate == null) return res2;
    // Servers may support multiple authentication methods so we need to find
    // the correct one
    final res2AuthenticateParts = res2Authenticate.split(',');
    String? rawMsg2;
    for (final res2AuthenticatePart in res2AuthenticateParts) {
      final trimmedPart = res2AuthenticatePart.trim();
      if (trimmedPart.startsWith('$headerPrefix ')) {
        rawMsg2 = trimmedPart;
        break;
      }
    }
    // If this isn't an NTLM request, return the initial response
    if (rawMsg2 == null) return res2;
    final msg2 = parseType2Message(
      rawMsg2,
      headerPrefix: headerPrefix,
    );
    // Discard the body so we can reuse the connection (required by NTLM)
    // await res2.stream.drain();

    // 3. Send the authenticated request
    final msg3 = createType3Message(
      msg2,
      domain: domain,
      workstation: workstation,
      username: username,
      password: password,
      headerPrefix: headerPrefix,
    );

    final res3 = await _inner.fetch<T>(
      requestOptions..headers[_authorizationHeader] = msg3,
    );

    return res3;
  }
}
