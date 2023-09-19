
// KCTF-KeyMEDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "KCTF-KeyME.h"
#include "KCTF-KeyMEDlg.h"
#include "afxdialogex.h"
#include "check.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#include <conio.h>			// cprintfͷ�ļ�
#endif



// TLS�ص�
void  WINAPI My_tls_callback(PVOID h, DWORD reason, PVOID pv)
{
	//MessageBoxA(NULL, "TLS", "TLS", MB_OK);
#ifdef _DEBUG
	_cprintf("TLS%d\n", 1);
#endif
	*(uint32_t*)(vm_data + 1122145) = 0xf496b3af; 					// QiXiVM�е�vm_data�еĵ�1122145������Ӧ����0xf496b3af��Ϊ���Ի�����ߣ��Ҹĳ���111 112 113 114��Ȼ��ʹ��TLS�Ļ���
}
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma section(".CRT$XLB",long,read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK _xl_y = My_tls_callback;
#pragma comment(linker, "/INCLUDE:__xl_y")



// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CKCTFKeyMEDlg �Ի���



CKCTFKeyMEDlg::CKCTFKeyMEDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_KCTFKEYME_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CKCTFKeyMEDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CKCTFKeyMEDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDCANCEL, &CKCTFKeyMEDlg::OnBnClickedCancel)
	ON_EN_CHANGE(IDC_EDIT2, &CKCTFKeyMEDlg::OnEnChangeEdit2)
	ON_BN_CLICKED(IDOK, &CKCTFKeyMEDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_MFCLINK2, &CKCTFKeyMEDlg::OnBnClickedMfclink2)
END_MESSAGE_MAP()


// CKCTFKeyMEDlg ��Ϣ�������

BOOL CKCTFKeyMEDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CKCTFKeyMEDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CKCTFKeyMEDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CKCTFKeyMEDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CKCTFKeyMEDlg::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnCancel();
}


void CKCTFKeyMEDlg::OnEnChangeEdit2()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CKCTFKeyMEDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	TCHAR t_user[256], t_serial_str[512];				// �����Ʋ���������ǿ��ַ�
	GetDlgItem(IDC_EDIT1)->GetWindowText(t_user, 256);
	GetDlgItem(IDC_EDIT2)->GetWindowText(t_serial_str, 512);

	//cprintf("%d", sizeof(t_user[0]));

	char user[256], serial_str[512];
	for (int i = 0; i < 256; i++)
		user[i] = (char)t_user[i];
	for (int i = 0; i < 512; i++)
		serial_str[i] = (char)t_serial_str[i];

#ifdef _DEBUG
	cprintf("user: %s\nserial_str: %s\n", user, serial_str);
#endif

	if (CheckSerial((char*)user, (char*)serial_str))
		MessageBox(TEXT("ע��ɹ�"), TEXT("ע��ɹ�"));
	else
		MessageBox(TEXT("ע��ʧ��"), TEXT("ע��ʧ��"));


	//CDialogEx::OnOK();
}


void CKCTFKeyMEDlg::OnBnClickedMfclink2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}
