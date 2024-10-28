#pragma once
#include "../Types.h"

#include "../Sniffer/tins.h"

namespace netlab 
{
	/*!
	    \fn size_t RawData(const class Tins::PDU &pdu, std::shared_ptr <std::vector<byte>> &buf, const size_t size);
	
	    \brief	Adapter to the Tins::sniffer that fills the #buf with the sniffed data based on Tins::sniffer
	
	    \param	pdu		   	The Tins::PDU.
	    \param [in,out]	buf	The buffer.
	
	    \return	A size_t.
	*/
	size_t RawData(const class Tins::PDU &pdu, std::shared_ptr <std::vector<byte>> &buf);

	size_t RawData(const Tins::PDU& pdu, uint8_t* buf, size_t size);

	/*!
	    \fn	std::string StrPort(uint16_t port_number);
	
	    \brief	port number to string, for error handling.
	
	    \param	port_number	The port number.
	
	    \return	A std::string.
	*/
	std::string StrPort(uint16_t port_number);

	uint8_t RNG8();
	uint16_t RNG16();
	uint32_t RNG32();

	//void printPDU(const ICMP& icmp, std::ostream& str);
}