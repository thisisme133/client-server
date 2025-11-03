#include "protected_function.hpp"

namespace protect
{
	/**
	 * @brief request function from server and wait for response
	 * @param marker_hash function marker hash
	 * @return true if request succeeded
	 */
	auto fn_protect_global_t::request_and_wait( uint32_t marker_hash ) -> bool
	{
		if ( !m_requester ) return false;

		/*
		   add pending request
		*/
		auto& pending{ pending_requests_t::instance( ) };
		auto req{ pending.add( marker_hash ) };

		/*
		   send request to server
		*/
		if ( !m_requester->request_function( marker_hash ) )
		{
			/*
			   CRITICAL: Clean up pending request on immediate send failure
			   Without this, the request would remain in the map forever (memory leak)
			*/
			pending.remove( marker_hash );
			return false;
		}

		/*
		   wait for response (timeout 5 seconds)
		*/
		return pending.wait_for( marker_hash, std::chrono::seconds( 5 ) );
	}

} // namespace protect
