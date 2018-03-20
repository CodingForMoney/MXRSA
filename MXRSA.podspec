Pod::Spec.new do |s|
	s.name         = "MXRSA"
	s.version      = "0.0.4"
	s.summary      = "MXRSA - 使用mbedtls的简单RSA工具库"

	s.homepage     = "https://github.com/CodingForMoney/MXRSA"
	s.authors      = { "lxm" => "luoxianmingg@gmail.com" }
	s.platform     = :ios, "7.0"
	s.source       = { :git => "https://github.com/CodingForMoney/MXRSA.git",:tag => s.version }
	s.license 	 = 'LICENSE'
    s.source_files = 'MXRSA/MXRSA.{h,m}'
	s.subspec 'mbedtls' do |sp|
		sp.source_files = 'MXRSA/mbedtls/*.{h,c}'
		sp.private_header_files = 'MXRSA/mbedtls/*.h'
	end
end
