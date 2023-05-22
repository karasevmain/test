// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "detours.h"
#pragma comment(lib,"Ws2_32.lib")
#include <WinSock2.h>

#include <iostream>
#include <string>
#include <mutex>

#pragma pack(1)
struct SPacketHeader
{
public:
	unsigned short mPacketSz;
	unsigned char mEncrypt;
	unsigned char mSeqNo;
	unsigned short mPacketId;
};
union USpeedInfo {
#pragma pack(1)
	struct SSpeedInfo {
		unsigned short mAttackRate;
		unsigned short mMoveRate;
	} mRate;
	int mSpeedInfo;
};

typedef int(_stdcall* pRecv)(SOCKET sock, char* buf, int len, int flags);
typedef int(_stdcall* pSend)(SOCKET sock, char* buf, int len, int flags);
pRecv _fRecv = (pRecv)(recv);
pSend _fSend = (pSend)(send);

char* mRcvBeginBuff = nullptr;
unsigned short mRcvBytesInBuffer = 0;

std::mutex mLocker;
SOCKET mDstSock = 0;
unsigned char mLastSeqNo;
bool mIsFirstPacket = true;

unsigned char mRecvBf[USHRT_MAX * 3];
int mRecvBfBytesCnt;

bool mEquipPacketIsSet = false;
unsigned char mEquipPacket[18];
bool mUnequipPacketIsSet = false;
unsigned char mUnequipPacket[7];
bool mDropPacketIsSet = false;
unsigned char mDropPacket[38];

bool mIsEquipTm = true;

bool mSpeedNotify = true;
USpeedInfo mSpeedInfo;

unsigned int mUnique = 0;

void sendMessageToClient(const char* pFormat, ...);
void sendPacketToClient(SPacketHeader* packet);
void sendPacket(SOCKET pDstSock, SPacketHeader* packet, int pFlags);

void spamDrop(int pCnt, int pMsDelay) {
	unsigned char aPacketToSend[38];

	for (int i(0); i < pCnt; ++i) {

		try {
			mLocker.lock();

			if (!mDropPacketIsSet) {

				mLocker.unlock();
				sendMessageToClient("Пакет выбрасывания предмета не сохранен. Выбросите предмет");
				return;
			}

			memcpy(aPacketToSend, mDropPacket, 38);

			mLocker.unlock();

			sendPacket(mDstSock, (SPacketHeader*)aPacketToSend, 0);
		}
		catch (...) {
			mLocker.unlock();
			throw;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(pMsDelay));
	}

}
void spamEquip(int pCnt) {
	unsigned char aPacketToSend[18];

	for (int i(0); i < pCnt; ++i) {

		try {
			mLocker.lock();

			if (!mEquipPacketIsSet) {

				mLocker.unlock();
				sendMessageToClient("Пакет экипировки не сохранен. Оденьте предмет.");
				return;
			}

			if (!mUnequipPacketIsSet) {

				mLocker.unlock();
				sendMessageToClient("Пакет снятия предмета не сохранен. Снимите предмет.");
				return;
			}

			if (mIsEquipTm) {

				memcpy(aPacketToSend, mEquipPacket, 18);
			}
			else {

				memcpy(aPacketToSend, mUnequipPacket, 7);

			}

			mLocker.unlock();

			sendPacket(mDstSock, (SPacketHeader*)aPacketToSend, 0);
		}
		catch (...) {
			mLocker.unlock();
			throw;
		}

		//	std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

}

void processPacket(SPacketHeader* packet, int* pSkip) {
	*pSkip = 0;

	switch (packet->mPacketId)
	{
	case 2033: /* отправка сообщения */ {
		char* aMessage = (char*)packet + 7;

		if (strstr(aMessage, "!help")) {
			*pSkip = 1;

			sendMessageToClient("Команда !razgon используется для разгона скорости атаки/бега, веса, восстановления хп от хилок.");
			sendMessageToClient("Напр. (!razgon 50) чем больше число тем сильнее будет разгон");
			sendMessageToClient("Команда !drop используется для быстрого выбрасывания предметов.");
			sendMessageToClient("Напр. (!drop 50 1) первое число - это кол-во предметов которое надо выбросить.");
			sendMessageToClient("второе число - это задержка между пакетами.");
			sendMessageToClient("Команда !snotify для включения/отключения отображения скорости персонажа. [0=выкл/1=вкл]");
		}
		else if (strstr(aMessage, "!razgon")) {
			*pSkip = 1;
			int aCnt = 0;

			if (sscanf(aMessage, "!razgon %d", &aCnt) > 0) {

				sendMessageToClient("Начинаю спам (%d раз)", aCnt);

				std::thread th(spamEquip, aCnt);
				th.detach();
			}
			else {
				sendMessageToClient("Команда !razgon используется для разгона скорости атаки/бега, веса, восстановления хп от хилок.");
				sendMessageToClient("Напр. (!razgon 50) чем больше число тем сильнее будет разгон");
			}
		}
		else if (strstr(aMessage, "!drop")) {
			*pSkip = 1;
			int aCnt = 0;
			int aDelayMs = 1;

			if (sscanf(aMessage, "!drop %d %d", &aCnt, &aDelayMs) > 1) {

				sendMessageToClient("Начинаю спам (%d раз / %d мс)", aCnt, aDelayMs);

				std::thread th(spamDrop, aCnt, aDelayMs);
				th.detach();
			}
			else {
				sendMessageToClient("Команда !drop используется для быстрого выбрасывания предметов.");
				sendMessageToClient("Напр. (!drop 50 1) первое число - это кол-во предметов которое надо выбросить.");
				sendMessageToClient("второе число - это задержка между пакетами.");
			}
		}
		else if (strstr(aMessage, "!snotify")) {
			*pSkip = 1;
			mSpeedNotify = !mSpeedNotify;

			sendMessageToClient("mSpeedNotify=%d", mSpeedNotify);
		}

	} break;
	case 1103: /* привествие от сервера */ {
		mLastSeqNo = 1;
	} break;
	case 5128: /* пакет экипировки (от клиента) */ {
		try {
			bool aNeedNotify = false;
			mLocker.lock();

			memcpy(mEquipPacket, packet, 18);

			if (!mEquipPacketIsSet)
				aNeedNotify = true;

			mEquipPacketIsSet = true;

			mLocker.unlock();

			if (aNeedNotify)
				sendMessageToClient("Пакет экипировки сохранен.");
		}
		catch (...) {
			mLocker.unlock();
			throw;
		}
	} break;
	case 5129: /* ответ от сервера на эквип вещи */ {
		mLocker.lock();

		mIsEquipTm = false;

		mLocker.unlock();
	} break;
	case 5130: /* пакет снятия предмета (от клиента) */ {
		try {
			bool aNeedNotify = false;
			mLocker.lock();

			memcpy(mUnequipPacket, packet, 7);

			if (!mUnequipPacketIsSet)
				aNeedNotify = true;

			mUnequipPacketIsSet = true;

			mLocker.unlock();

			if (aNeedNotify)
				sendMessageToClient("Пакет снятия экипировки сохранен.");
		}
		catch (...) {
			mLocker.unlock();
			throw;
		}
	} break;
	case 5131: /* ответ от сервера на снятие вещи */ {
		mLocker.lock();

		mIsEquipTm = true;

		mLocker.unlock();
	} break;
	case 5159: /* дроп предмета */ {

		try {
			bool aNeedNotify = false;
			mLocker.lock();

			memcpy(mDropPacket, packet, 38);

			if (!mDropPacketIsSet)
				aNeedNotify = true;

			mDropPacketIsSet = true;

			mLocker.unlock();

			if (aNeedNotify)
				sendMessageToClient("Пакет выбрасывания предмета сохранен.");
		}
		catch (...) {
			mLocker.unlock();
			throw;
		}
	} break;
	case 5117: {
		mUnique = *(unsigned int*)((char*)packet + 6);
		sendMessageToClient("mUnique=%u", mUnique);
	} break;
	case 5147: {
		USpeedInfo aInfo = *(USpeedInfo*)((char*)packet + 6);
		unsigned int aUnique = *(unsigned int*)((char*)packet + 10);
		if (aInfo.mSpeedInfo != mSpeedInfo.mSpeedInfo && mSpeedNotify && aUnique == mUnique)
		{
			mSpeedInfo = aInfo;
			sendMessageToClient("Задержка между атаками: %d (мс), Скорость бега: %d", mSpeedInfo.mRate.mAttackRate, mSpeedInfo.mRate.mMoveRate);
		}
	} break;
	default:
		break;
	}
}

void createPacketIn(unsigned char* pDst, unsigned short pSize, unsigned char pEncrypt, unsigned char pSeqNo, unsigned short pId) {
	if (pSize > 6)
		memset(pDst + 6, 0, pSize - 6);

	SPacketHeader* aHeader = (SPacketHeader*)pDst;

	aHeader->mPacketSz = pSize;
	aHeader->mEncrypt = pEncrypt;
	aHeader->mSeqNo = pSeqNo;
	aHeader->mPacketId = pId;
}

thread_local char _TextBuff[1024];

void sendMessageToClient(const char* pFormat, ...) {
	va_list args;
	va_start(args, pFormat);
	vsprintf(_TextBuff, pFormat, args);
	va_end(args);

	unsigned char aMessagePacket[141];
	createPacketIn(aMessagePacket, 141, 0, 0, 2034);

	strcpy((char*)(aMessagePacket + 25), "1502Enjoyer");
	int aLen = strlen(_TextBuff);

	if (aLen > 100)
		aLen = 100;

	strcpy((char*)(aMessagePacket + 40), _TextBuff);

	sendPacketToClient((SPacketHeader*)(aMessagePacket));
}
void sendPacketToClient(SPacketHeader* packet) {
	try {
		mLocker.lock();

		if (mRecvBfBytesCnt + packet->mPacketSz > sizeof(mRecvBf)) {
			mLocker.unlock();
			return;
		}

		memcpy(mRecvBf + mRecvBfBytesCnt, packet, packet->mPacketSz);
		mRecvBfBytesCnt += packet->mPacketSz;

		mLocker.unlock();
	}
	catch (...) {
		mLocker.unlock();
		throw;
	}
}

int _stdcall recvHook(SOCKET sock, char* buf, int len, int flags) {
	int aRcvResult = _fRecv(sock, buf, len, flags);

	if (aRcvResult > 0)
	{
		if (mRcvBeginBuff == nullptr)
			mRcvBeginBuff = buf;

		mRcvBytesInBuffer += aRcvResult;

		int aOffset = 0;
		int aIndex = 0;

		for (unsigned short* aPacketSz = (unsigned short*)mRcvBeginBuff; mRcvBytesInBuffer > 0 && mRcvBytesInBuffer >= *aPacketSz; aPacketSz = (unsigned short*)(mRcvBeginBuff + aOffset))
		{
			int aSkip = 0;
			processPacket((SPacketHeader*)(mRcvBeginBuff + aOffset), &aSkip);
			mRcvBytesInBuffer -= *aPacketSz;
			aOffset += *aPacketSz;

			if (mRcvBytesInBuffer == 0)
			{

				try {
					mLocker.lock();

					if (mRecvBfBytesCnt > 0)
					{
						if (len - aOffset > mRecvBfBytesCnt)
						{
							memcpy(mRcvBeginBuff + aOffset, mRecvBf, mRecvBfBytesCnt);
							int aReadedBytes = mRecvBfBytesCnt;

							mRecvBfBytesCnt = 0;
							mLocker.unlock();

							mRcvBeginBuff = nullptr;
							mRcvBytesInBuffer = 0;

							return aRcvResult + aReadedBytes;
						}
					}

					mLocker.unlock();
				}
				catch (...) {
					mLocker.unlock();
					throw;
				}

				break;
			}
		}
	}

	return aRcvResult;
}

int getSeqNo(SOCKET pSock) {
	return mLastSeqNo++;
}

void sendPacket(SOCKET pDstSock, SPacketHeader* packet, int pFlags) {
	try
	{
		mLocker.lock();

		if (mIsFirstPacket) {
			if (packet->mEncrypt)
				mLastSeqNo = packet->mSeqNo ^ 0x8A;
			else
				mLastSeqNo = packet->mSeqNo;

			mIsFirstPacket = false;
		}

		packet->mSeqNo = getSeqNo(pDstSock);

		if (packet->mEncrypt == 1)
			packet->mSeqNo ^= 0x8A;

		mDstSock = pDstSock;

		DWORD oldLastError = WSAGetLastError();

		int aBytesSended = 0;

		int nSelectCnt = 0;
		struct timeval tv;

		fd_set fd;

		do
		{
			int aResultSend = _fSend(pDstSock, (char*)packet + aBytesSended, packet->mPacketSz - aBytesSended, pFlags);

			if (aResultSend == -1)
			{
				if (WSAGetLastError() == WSAEWOULDBLOCK)
				{
				retry_select:;
					++nSelectCnt;

					if (nSelectCnt > 5) {
						mLocker.unlock();
						return;
					}

					tv.tv_sec = 1;
					tv.tv_usec = 0;
					FD_ZERO(&fd);
					FD_SET(pDstSock, &fd);

					int aSelectResult = select(1, NULL, &fd, NULL, &tv);

					if (aSelectResult > 0)
						continue;
					else if (aSelectResult == 0)
						goto retry_select;
					else
					{
						mLocker.unlock();
						return;
					}
				}
				else {
					mLocker.unlock();
					return;
				}
			}
			else
				aBytesSended += aResultSend;
		} while (aBytesSended != packet->mPacketSz);

		WSASetLastError(oldLastError);

		mLocker.unlock();
	}
	catch (...) {
		mLocker.unlock();
		throw;
	}
}

int _stdcall sendHook(SOCKET sock, char* buf, int len, int flags) {

	int aSkip = 0;
	processPacket((SPacketHeader*)(buf), &aSkip);

	if (aSkip == 0)
		sendPacket(sock, (SPacketHeader*)buf, flags);

	return len;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		int aSndAttachResult = DetourAttach(&(PVOID&)_fSend, sendHook);
		int aRcvAttachResult = DetourAttach(&(PVOID&)_fRecv, recvHook);
		DetourTransactionCommit();
	} break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

