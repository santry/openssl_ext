module OpenSSL
  class Digest
    macro def_digest_classes(names)
      {% for name in names %}
        class {{name.id}} < Digest
          def self.new
            new("{{name.id}}", new_evp_mt_ctx("{{name.id}}"))
          end
					private def self.new_evp_mt_ctx(name)
      md = LibCrypto.evp_get_digestbyname(name)
      unless md
        raise UnsupportedError.new("Unsupported digest algorithm: #{name}")
      end
      ctx = LibCrypto.evp_md_ctx_new
      unless ctx
        raise Error.new "Digest initialization failed."
      end
      if LibCrypto.evp_digestinit_ex(ctx, md, nil) != 1
        raise Error.new "Digest initialization failed."
      end
      raise Error.new("Invalid EVP_MD_CTX") unless ctx
      ctx
    end
        end
      {% end %}
    end

    def_digest_classes %w(DSS DSS1 MD2 MD4 MD5 MDC2 RIPEMD160 SHA SHA1 SHA224 SHA256 SHA384 SHA512)

  end
end
