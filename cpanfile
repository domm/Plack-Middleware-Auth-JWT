# This file is generated by Dist::Zilla::Plugin::CPANFile v6.024
# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "Crypt::JWT" => "0.020";
requires "Plack::Middleware" => "0";
requires "Plack::Request" => "0";
requires "Plack::Util" => "0";
requires "Plack::Util::Accessor" => "0";
requires "parent" => "0";
requires "perl" => "5.010";

on 'build' => sub {
  requires "Module::Build" => "0.28";
};

on 'test' => sub {
  requires "File::Spec" => "0";
  requires "File::Temp" => "0";
  requires "FindBin" => "0";
  requires "HTTP::Request::Common" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Plack::Builder" => "0";
  requires "Plack::Test" => "0";
  requires "Test::More" => "0";
};

on 'configure' => sub {
  requires "Module::Build" => "0.28";
};
