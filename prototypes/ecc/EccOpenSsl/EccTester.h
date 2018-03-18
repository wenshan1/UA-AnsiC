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
		void Decode(String^ requestPath, String^ responsePath, array<unsigned char>^% clientSecret, array<unsigned char>^% serverSecret);
		void SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
	};
}
