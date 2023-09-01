import 'package:ntlm/ntlm.dart';

void main() {
  var client = NTLMClient(
    domain: '',
    workstation: 'LAPTOP',
    username: 'User208',
    password: 'password',
  );

  client.getUri(Uri.parse('https://example.com/')).then((res) {
    print(res.data);
  });
}
