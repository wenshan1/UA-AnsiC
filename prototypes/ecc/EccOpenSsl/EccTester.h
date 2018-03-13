#pragma once

using namespace System;

namespace EccOpenSsl {

	class EccTesterData;

	public ref class EccTester
	{
		EccTesterData* m_p;

	public:
		EccTester();
		~EccTester();

		void Initialize();
		void Cleanup();

		void Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
		array<unsigned char>^ Decode(String^ requestPath, String^ responsePath);
		void SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
	};
}
