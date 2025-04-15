package awskms

import (
	"context"
	"fmt"
	"iter"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/pkix"
	awsutils "github.com/signatory-io/signatory-core/utils/aws"
	"github.com/signatory-io/signatory-core/vault"
)

type KMSVault struct {
	client *kms.Client
}

type kmsKey struct {
	id  *string
	pub *ecdsa.PublicKey
	v   *KMSVault
}

func algorithmFromKeySpec(ks types.KeySpec) crypto.Algorithm {
	switch ks {
	case types.KeySpecEccNistP256:
		return crypto.ECDSA_P256
	case types.KeySpecEccNistP384:
		return crypto.ECDSA_P384
	case types.KeySpecEccNistP521:
		return crypto.ECDSA_P521
	case types.KeySpecEccSecgP256k1:
		return crypto.ECDSA_Secp256k1
	default:
		return 0
	}
}

func (k *kmsKey) Algorithm() crypto.Algorithm {
	return k.pub.PublicKeyType()
}

func (k *kmsKey) PublicKey() crypto.PublicKey { return k.pub }

func getHash(opts crypto.SignOptions) crypto.Hash {
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			return h
		}
	}
	return nil
}

func (k *kmsKey) SignMessage(ctx context.Context, message []byte, sc vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	var hash crypto.Hash
	if h := getHash(opts); h != nil {
		hash = h
	} else {
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(message)
	return k.SignDigest(ctx, h.Sum(nil), sc, opts)
}

func (k *kmsKey) SignDigest(ctx context.Context, digest []byte, sc vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	if len(digest) != crypto.SHA256.Size() {
		return nil, vault.WrapError(k.v, fmt.Errorf("digest must be %d bytes long", crypto.SHA256.Size()))
	}
	out, err := k.v.client.Sign(ctx, &kms.SignInput{
		KeyId:            k.id,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, vault.WrapError(k.v, err)
	}
	sig, err := ecdsa.NewSignatureFromDERBytes(out.Signature, k.pub.Curve)
	if err != nil {
		return nil, vault.WrapError(k.v, fmt.Errorf("%s: %w", *k.id, err))
	}
	if opts, ok := opts.(*ecdsa.Options); ok {
		if opts.GenerateRecoveryCode {
			sig, err = ecdsa.GenerateRecoveryCode(sig, k.pub, digest)
			if err != nil {
				return nil, vault.WrapError(k.v, fmt.Errorf("%s: %w", *k.id, err))
			}
		}
	}
	return sig, nil
}

func (k *kmsKey) Vault() vault.Vault { return k.v }

func (k *kmsKey) ID() string { return *k.id }

type kmsIterator struct {
	ctx    context.Context
	filter map[crypto.Algorithm]struct{}
	v      *KMSVault
	err    error
}

func (it *kmsIterator) Err() error { return it.err }
func (it *kmsIterator) Keys() iter.Seq[vault.KeyReference] {
	if it.err != nil {
		return func(func(vault.KeyReference) bool) {}
	}
	return func(yield func(vault.KeyReference) bool) {
		var out *kms.ListKeysOutput
		for {
			var inp *kms.ListKeysInput
			if out != nil {
				if out.NextMarker == nil {
					break
				}
				inp = &kms.ListKeysInput{
					Marker: out.NextMarker,
				}
			}
			var err error
			if out, err = it.v.client.ListKeys(it.ctx, inp); it.err != nil {
				it.err = vault.WrapError(it.v, err)
				return
			}
			for _, entry := range out.Keys {
				key, err := it.v.getPublicKey(it.ctx, entry.KeyId, it.filter)
				if err != nil {
					it.err = vault.WrapError(it.v, err)
					return
				}
				if key != nil && !yield(key) {
					return
				}
			}
		}
	}
}

type errAlgo struct {
	value any
}

func (e errAlgo) Error() string        { return fmt.Sprintf("unsupported key type: %T", e.value) }
func (d errAlgo) Is(target error) bool { return target == vault.ErrAlgorithm }

func (v *KMSVault) getPublicKey(ctx context.Context, keyID *string, filter map[crypto.Algorithm]struct{}) (*kmsKey, error) {
	resp, err := v.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: keyID,
	})
	if err != nil {
		return nil, err
	}

	alg := algorithmFromKeySpec(resp.KeySpec)
	if _, ok := filter[alg]; resp.KeyUsage != types.KeyUsageTypeSignVerify ||
		alg == 0 || (filter != nil && !ok) {
		return nil, nil
	}

	p, err := pkix.ParsePublicKey(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	pub, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, errAlgo{value: p}
	}
	return &kmsKey{
		pub: pub,
		id:  resp.KeyId,
		v:   v,
	}, nil
}

// List returns a list of keys stored under the backend
func (v *KMSVault) List(ctx context.Context, filter []crypto.Algorithm) vault.KeyIterator {
	f := make(map[crypto.Algorithm]struct{})
	for _, alg := range filter {
		f[alg] = struct{}{}
	}
	return &kmsIterator{
		ctx:    ctx,
		v:      v,
		filter: f,
	}
}

func (v *KMSVault) InstanceInfo() string { return "AWS KMS" }

func (v *KMSVault) Name() string { return "awskms" }

func (v *KMSVault) Close(context.Context) error { return nil }

func (v *KMSVault) Ready(context.Context) (bool, error) { return true, nil }

type fact struct{}

func (fact) New(ctx context.Context, opt vault.GlobalOptions, config any) (vault.Vault, error) {
	c := config.(*awsutils.Config)
	cfg, err := awsutils.NewAWSConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg)
	return &KMSVault{
		client: client,
	}, nil
}

func (fact) DefaultConfig() any {
	return new(awsutils.Config)
}

func init() {
	vault.Register("awskms", fact{})
}
